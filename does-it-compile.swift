#!/usr/bin/swift

import WebKit
import Foundation

/// Compile a content blocker list synchronously, must be run on background thread
func synchronousCompileList(_ list: String, to ruleStore: WKContentRuleListStore = .default()!) -> Bool {
  let group = DispatchGroup()
  var result = true
  
  group.enter()
  ruleStore.compileContentRuleList(forIdentifier: "list", encodedContentRuleList: list, completionHandler: { list, error in
    result = (error == nil)
    group.leave()
  })
  group.wait()
  return result
}

let compileQueue = DispatchQueue(label: "compile")
var anyFailed = false

for path in CommandLine.arguments.dropFirst().map({ NSString(string: $0) }) {
  guard let list = try? String(contentsOfFile: path.expandingTildeInPath) else {
    print("Failed to load \"\(path)\" to compile")
    continue
  }
  compileQueue.async {
    let timeStart = Date()
    print("Compiling: \(path.lastPathComponent)", terminator: "")
    if synchronousCompileList(list) {
      print("... ✓", terminator: "")
    } else {
      print("... 𐄂", terminator: "")
      anyFailed = true
    }
    print("\(String(format: " (%.02fs)", Date().timeIntervalSince(timeStart)))")
  }
}

compileQueue.async {
  exit(anyFailed ? EXIT_FAILURE : EXIT_SUCCESS)
}

RunLoop.main.run()
