#!/usr/bin/env python
# -*- coding: utf-8 -*-
# ab2cb: convert AdBlock content filters to Safari Content Blockers
# https://github.com/bnomis/ab2cb
# (c) Simon Blanchard

import json
import os
import os.path
import re
import sys
import copy

from .logger import error, init_logging

# lifted from ABP/filterClasses.js
elemhideRegExp = re.compile(r'^([^\/\*\|\@"!]*?)#(\@)?(?:([\w\-]+|\*)((?:\([\w\-]+(?:[$^*]?=[^\(\)"]*)?\))*)|#([^{}]+))$')
regexpRegExp = re.compile(r'^(@@)?\/.*\/(?:\$~?[\w\-]+(?:=[^,\s]+)?(?:,~?[\w\-]+(?:=[^,\s]+)?)*)?$')
optionsRegExp = re.compile(r'\$(~?[\w\-]+(?:=[^,]+)?(?:,~?[\w\-]+(?:=[^,\s]+)?)*)$')

RegExpFilter_typeMap = {
    'OTHER': 1,
    'SCRIPT': 2,
    'IMAGE': 4,
    'STYLESHEET': 8,
    'OBJECT': 16,
    'SUBDOCUMENT': 32,
    'DOCUMENT': 64,
    'XBL': 1,
    'PING': 1,
    'XMLHTTPREQUEST': 2048,
    'OBJECT_SUBREQUEST': 4096,
    'DTD': 1,
    'MEDIA': 16384,
    'FONT': 32768,

    'BACKGROUND': 4,

    'POPUP': 0x10000000,
    'ELEMHIDE': 0x40000000
}

UnsupportedContentTypes = [
    'OTHER',
    'OBJECT',
    'XBL',
    'PING',
    'OBJECT_SUBREQUEST',
    'DTD',
    'FONT',
    'BACKGROUND',
    'ELEMHIDE',
    'CSP'
]

RegExpFilter_prototype_contentType = 0x7FFFFFFF

RegExpFilter_prototype_contentType &= ~(RegExpFilter_typeMap['DOCUMENT'] | RegExpFilter_typeMap['ELEMHIDE'] | RegExpFilter_typeMap['POPUP'])


# clean up a regex
regex_cleaners = [
    (re.compile(r'\*+'), r"*"),    # remove multiple wildcards
    (re.compile(r'\^\|$'), r"^"),  # remove anchors following separator placeholder
    (re.compile(r'([.*+?^${}()|[\]\\])'), r"\\\1"),  # escape special symbols
    (re.compile(r'\\\*'), r".*"),  # replace wildcards by .*
    (re.compile(r'^\\\|'), r"^"),  # process anchor at expression start
    (re.compile(r'\\\|$'), r"$"),  # process anchor at expression end
    (re.compile(r'^(\\\.\\\*)'), r''),  # remove leading wildcards
    (re.compile(r'(\\\.\\\*)$'), r''),  # remove trailing wildcards
]

def is_ascii(s):
    return all(ord(c) < 128 for c in s)

def writerr(options, line, exception=None, set_exit_status=True):
    if set_exit_status:
        options.exit_status = 'error'
    options.stderr.write(line + '\n')
    if exception:
        error(line, exc_info=True)


def writerr_file_access(options, line, exception=None):
    if not options.suppress_file_access_errors:
        writerr(options, line, exception=exception, set_exit_status=False)


def check_file_access(options, path):
    # check file exists
    # will return true even for broken symlinks
    if not os.path.lexists(path):
        writerr_file_access(options, 'File does not exist: %s' % path)
        return False

    # double check for broken symlinks
    if os.path.islink(path):
        if not os.path.exists(path):
            writerr_file_access(options, 'Broken symlink: %s' % path)
            return False

    # check can open for read
    if os.path.isdir(path):
        if not os.access(path, os.R_OK):
            writerr_file_access(options, 'Directory is not readable: %s' % path)
            return False
    else:
        try:
            fp = open(path)
        except Exception as e:
            writerr_file_access(options, 'File is not readable: %s' % path)
            error('check_file_access: exception for %s: %s' % (path, e), exc_info=True)
            return False
        else:
            fp.close()

    return True


def elem_hide_from_text(text, domain, isException, tagName, attrRules, selector):
    #print("Hide: '%s' '%s' '%s' '%s' '%s' '%s'" % (text, domain, isException, tagName, attrRules, selector))
    filter = {
        'trigger': {
            'url-filter': '.*'
        },
        'action': {
            'type': 'css-display-none',
            'selector': selector
        }
    }
    if domain:
        if isException:
            filter['trigger']['unless-domain'] = domain.split(',')
        else:
            filter['trigger']['if-domain'] = domain.lower().split(',')

    return [filter]


def regex_filters(origText, regexpSource, contentType, matchCase, domains, firstParty, thirdParty, sitekeys, isException):
    anchor = False
    requires_scheme = False
    length = len(regexpSource)
    if length == 0: 
        return None
    # already a regex
    if length >= 2 and regexpSource[0] == '/' and regexpSource[-1] == '/':
        return None
    else:
        regex = regexpSource
        if regex[0:2] == '||':
            regex = regex[2:]
            requires_scheme = True
        elif regex[0] == '|':
            regex = regex[1:]
            anchor = True
        if len(regex) > 0 and regex[-1] == '^':
            regex = regex[0:-1]
        for r in regex_cleaners:
            #print('In: %s' % regex)
            regex = r[0].sub(r[1], regex)
            #print('Out: %s' % regex)
        #print('Before: %s  After: %s' % (regexpSource, regex))

    if regex[0:3] != '://' and requires_scheme:
        regex = '^[^:]+:(//)?([^/]+.)?' + regex
        
    if anchor:
        regex = "^" + regex
    
    if len(regex) == 0:
        print("Skipping \"%s\" due to empty post-processed regex url-filter" % origText) 
        return None
        
    if not is_ascii(regex):
        return None

    filter = {
        'trigger': {
            'url-filter': regex
        },
        'action': {
            'type': 'block'
        }
    }
    if matchCase: 
        filter['trigger']['url-filter-is-case-sensitive'] = True
    if thirdParty:
        filter['trigger']['load-type'] = ['third-party']
    if firstParty:
        filter['trigger']['load-type'] = ['first-party']
    if domains:
        ifd = []
        unl = []
        domain_list = __builtins__.filter(len, domains.lower().split('|'))
        for d in domain_list:
            if d[0] == '~':
                encoded = punycode(d[1:])
                if not encoded:
                    return None
                unl.append('*' + encoded)
            else:
                encoded = punycode(d)
                if not encoded:
                    return None
                ifd.append('*' + encoded)
        if ifd and unl:
            # Invalid rule, needs a split
            # print('Invalid: %s (Needs rule split due to mixed domain restrictions)' % origText)
            return None
        else:
            if ifd:
                filter['trigger']['if-domain'] = ifd
            if unl:
                filter['trigger']['unless-domain'] = unl

    if contentType:
        if contentType & RegExpFilter_typeMap['DOCUMENT'] and isException:
            # print('Invalid: %s ($document exceptions are not supported)' % origText)
            return None
            
        rt = []
        if contentType & RegExpFilter_typeMap['DOCUMENT'] or contentType & RegExpFilter_typeMap['SUBDOCUMENT']:
            rt.append('document')
        if contentType & RegExpFilter_typeMap['IMAGE']:
            rt.append('image')
        if contentType & RegExpFilter_typeMap['STYLESHEET']:
            rt.append('style-sheet')
        if contentType & RegExpFilter_typeMap['SCRIPT']:
            rt.append('script')
        if contentType & RegExpFilter_typeMap['FONT']:
            rt.append('font')
        if contentType & RegExpFilter_typeMap['XMLHTTPREQUEST']:
            rt.append('raw')
        if contentType & RegExpFilter_typeMap['MEDIA']:
            rt.append('media')
        if contentType & RegExpFilter_typeMap['POPUP']:
            rt.append('popup')
        if rt:
            filter['trigger']['resource-type'] = rt
    
        if len(rt) > 1 and 'document' in rt and not (firstParty or thirdParty):
            # Split the rule up into 2 to only block third-party documents
            splitFilter = copy.deepcopy(filter)
            splitFilter['trigger']['resource-type'] = ['document']
            splitFilter['trigger']['load-type'] = ['third-party']
            filter['trigger']['resource-type'] = rt[1:]
            print("Split %s into 2 rules" % origText)
            return [filter, splitFilter]
            
    return [filter]


def blocking_filters(origText, regexpSource, contentType, matchCase, domains, firstParty, thirdParty, sitekeys, collapse):
    #print("Blocking: '%s' '%s' '%s' '%s' '%s' '%s' '%s' '%s'" % (origText, regexpSource, contentType, matchCase, domains, thirdParty, sitekeys, collapse))
    return regex_filters(origText, regexpSource, contentType, matchCase, domains, firstParty, thirdParty, sitekeys, False)


def whitelist_filters(origText, regexpSource, contentType, matchCase, domains, firstParty, thirdParty, sitekeys):
    #print("White: '%s' '%s' '%s' '%s' '%s' '%s' '%s'" % (origText, regexpSource, contentType, matchCase, domains, thirdParty, sitekeys))
    filters = regex_filters(origText, regexpSource, contentType, matchCase, domains, firstParty, thirdParty, sitekeys, True)
    if filters:
        for f in filters:
            f['action']['type'] = 'ignore-previous-rules'
    return filters

# Rules that should default to third-party load type unless specified via $first-party/$~third-party
DefaultThirdPartyRules = [
    "&adurl=",
    "&adgroupid=",
    "&AdType=",
    "/ad1.$domain=~ad1.de|~ad1.in|~vereinslinie.de",
]

def regex_from_text(text):
    origText = text
    blocking = True
    # whitelist?
    white_pos = text.find('@@')
    if white_pos == 0:
        blocking = False
        text = text[2:]

    # set up values for options if set
    contentType = None
    matchCase = None
    domains = None
    sitekeys = None
    thirdParty = text in DefaultThirdPartyRules
    firstParty = None
    collapse = None

    match = None
    dollar_pos = text.find('$')
    if dollar_pos >= 0:
        match = optionsRegExp.search(text)

    # read the options
    if match:
        options = match.group(1).upper().split(",")
        text = text[:dollar_pos]
        for option in options:
            value = None
            separatorIndex = option.find("=")
            if separatorIndex >= 0:
                try:
                    value = option[separatorIndex + 1:]
                except:
                    print('bad value')
                    pass
                option = option[:separatorIndex]

            option = option.replace('-', "_")
            if option in RegExpFilter_typeMap and option not in UnsupportedContentTypes:
                if contentType is None:
                    contentType = 0
                contentType |= RegExpFilter_typeMap[option]

            elif option[0] == "~" and option[1:] in RegExpFilter_typeMap:
                if contentType is None:
                    contentType = RegExpFilter_prototype_contentType
                contentType &= ~RegExpFilter_typeMap[option[1:]]

            elif option == "MATCH_CASE":
                matchCase = True

            elif option == "~MATCH_CASE":
                matchCase = False

            elif option == "DOMAIN" and value:
                domains = value

            elif option == "THIRD_PARTY" or option == "~FIRST_PARTY":
                thirdParty = True
                firstParty = False

            elif option == "~THIRD_PARTY" or option == "FIRST_PARTY":
                thirdParty = False
                firstParty = True

            elif option == "COLLAPSE":
                collapse = True

            elif option == "~COLLAPSE":
                collapse = False

            elif option == "SITEKEY" and value:
                sitekeys = value

            else:
#                print('Invalid: %s' % origText)
                return None

    if blocking:
        return blocking_filters(origText, text, contentType, matchCase, domains, firstParty, thirdParty, sitekeys, collapse)
    return whitelist_filters(origText, text, contentType, matchCase, domains, firstParty, thirdParty, sitekeys)

def punycode(text):
    if is_ascii(text):
        return text
    try:
        # Attempt to encode Punycode
        return str(text.encode('idna'))[2:-1] # (Remove b'')
    except:
        return None

def filter_from_text(text, options):
    match = None
    hash_pos = text.find('#')
    if hash_pos >= 0:
        match = elemhideRegExp.search(text)
    if match:
        if options.no_css:
            return None
        return elem_hide_from_text(text, match.group(1), match.group(2), match.group(3), match.group(4), match.group(5))
    return regex_from_text(text)


def ab2cb_fp(options, fp):
    rules = []
    acceptedLines = []
    for l in fp.readlines():
        l = l.strip()
        if not l:
            continue
        if l[0] == '[':
            continue
        if l[0] == '!':
            continue

        line_rules = filter_from_text(l, options)
        if line_rules:
            rules.extend(line_rules)
            if l in DefaultThirdPartyRules:
                if "$" in l:
                    acceptedLines.append(l + ",third-party")
                else:
                    acceptedLines.append(l + "$third-party")
            else:
                acceptedLines.append(l)
    return (rules, acceptedLines)


def ab2cb_file(options, path):
    if not check_file_access(options, path):
        return

    rules = []
    with open(path) as fp:
        rules = ab2cb_fp(options, fp)
    return rules


def write_rules(options, rulesAndLines):
    if not rulesAndLines or not rulesAndLines[0]:
        return
    
    rules = rulesAndLines[0]
    lines = rulesAndLines[1]

    fp = options.stdout
    if options.output:
        try:
            fp = open(options.output, 'w')
        except Exception as e:
            writerr_file_access(options, 'Cannot open output file: %s' % options.output)
            error('write_rules: exception for %s: %s' % (options.output, e), exc_info=True)
            return
            
    if options.output_rules:
        try:
            rulesfp = open(options.output_rules, 'w')
            rulesfp.write('\n'.join(lines) + '\n')
            rulesfp.close()
        except Exception as e:
            writerr_file_access(options, 'Cannot open output file: %s' % options.output_rules)
            error('write_rules: exception for %s: %s' % (options.output_rules, e), exc_info=True)
            return

    black = []
    white = []
    for r in rules:
        if r['action']['type'] == 'ignore-previous-rules':
            white.append(r)
        else:
            black.append(r)

    out = black + white

    if options.strip_whitespace:
        json.dump(out, fp, separators=(',', ':'))
    else:
        json.dump(out, fp, indent=4)
        
    print("\nGenerated a total of %d rules (%d blocks, %d exceptions)\n\n" % (len(out), len(black), len(white)))


def ab2cb(options):
    rules = ([], [])
    if options.files:
        for f in options.files:
            file_rules = ab2cb_file(options, f)
            rules[0].extend(file_rules[0])
            rules[1].extend(file_rules[1])
            print("Generated %d rules for %s" % (len(file_rules[1]), f))
    else:
        rules = ab2cb_fp(options, options.stdin)
    write_rules(options, rules)


def main(argv, stdin=None, stdout=None, stderr=None):
    from .options import parse_opts
    exit_statuses = {
        'extracted': 0,
        'no-extract': 1,
        'error': 2,
        'not-set': -1
    }

    options = parse_opts(argv, stdin=stdin, stdout=stdout, stderr=stderr)
    if not options:
        return exit_statuses['error']

    init_logging(options)

    # do the convertion
    try:
        ab2cb(options)
    except KeyboardInterrupt:
        writerr(options, '\nInterrupted')
    except Exception as e:
        print("ab2cb exception: %s" % e)
        writerr(options, 'ab2cb exception', exception=e)
        options.exit_status = 'error'
        raise e

    if options.exit_status == 'not-set':
        if options.did_extract:
            options.exit_status = 'extracted'
        else:
            options.exit_status = 'no-extract'

    return exit_statuses[options.exit_status]


def run():
    sys.exit(main(sys.argv[1:]))


if __name__ == '__main__':
    run()


