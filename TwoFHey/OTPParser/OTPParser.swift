import Foundation
import AppKit

public struct ParsedOTP {
  public init(service: String?, code: String) {
    self.service = service
    self.code = code
  }

  public let service: String?
  public let code: String

  func copyToClipboard() -> String?  {
    // Check for setting here to avoid reading from clipboard unnecessarily
    let originalContents = AppStateManager.shared.restoreContentsEnabled ? NSPasteboard.general.string(forType: .string) : nil

    NSPasteboard.general.clearContents()
    NSPasteboard.general.setString(code, forType: .string)

    return originalContents;
  }
}

extension ParsedOTP: Equatable {
  static public func == (lhs: Self, rhs: Self) -> Bool {
    return lhs.service == rhs.service && lhs.code == rhs.code
  }
}

extension String {
  var withNonDigitsRemoved: Self? {
    guard let regExp = try? NSRegularExpression(pattern: #"[^\d.]"#, options: .caseInsensitive) else { return nil }
    let range = NSRange(location: 0, length: self.utf16.count)

    // Replace non-digits and non-decimal points with an empty string
    let cleanedString = regExp.stringByReplacingMatches(in: self, options: [], range: range, withTemplate: "")

    // Check if the cleaned string contains a decimal point
    if cleanedString.contains(".") {
      // If it does, return the cleaned string
      return cleanedString
    } else {
      // Otherwise, return nil to indicate that the original string should be used
      return nil
    }
  }
}


protocol OTPParser {
  func parseMessage(_ message: String) -> ParsedOTP?
}

public class TwoFHeyOTPParser: OTPParser {
  var config: OTPParserConfiguration

  public init(withConfig config: OTPParserConfiguration) {
    self.config = config
  }

  public func parseMessage(_ message: String) -> ParsedOTP? {
    let lowercaseMessage = message.lowercased()
    print("Lowercase Message: \(lowercaseMessage)")

    // Check if the message contains a phone number pattern
    let phoneNumberPattern = #"\b\d{3}[-.\s]?\d{3}[-.\s]?\d{4}\b"#
    let phoneNumberRegex = try! NSRegularExpression(pattern: phoneNumberPattern)
    let phoneNumberMatches = phoneNumberRegex.matches(in: message, options: [], range: NSRange(location: 0, length: message.utf16.count))

    // If a phone number pattern is found, return nil to ignore the message
    if !phoneNumberMatches.isEmpty {
      print("Message contains a phone number, ignoring...")
      return nil
    }

    print("Google OTP: \(OTPParserConstants.googleOTPRegex.firstCaptureGroupInString(message))")

    let service = inferServiceFromMessage(message)
    print("Inferred Service: \(service ?? "Unknown")")

    let standardRegExps: [NSRegularExpression] = [
      OTPParserConstants.CodeMatchingRegularExpressions.standardFourToEight,
      OTPParserConstants.CodeMatchingRegularExpressions.dashedThreeAndThree,
      OTPParserConstants.CodeMatchingRegularExpressions.alphanumericWordContainingDigits,
    ]

    for customPattern in config.customPatterns {
      print("Custom Pattern Service Name: \(customPattern.serviceName ?? "Unknown")")
      print("Custom Pattern Matcher Pattern: \(customPattern.matcherPattern)")
      if let matchedCode = customPattern.matcherPattern.firstCaptureGroupInString(lowercaseMessage) {
        print("Custom pattern matched. Code: \(matchedCode)")
        return ParsedOTP(service: customPattern.serviceName, code: matchedCode)
      }
    }

    for regex in standardRegExps {
      let matches = regex.matchesInString(lowercaseMessage)
      for match in matches {
        guard let code = match.firstCaptureGroupInString(lowercaseMessage) else { continue }

        print("Standard regex match. Code: \(code)")

        if isValidCodeInMessageContext(message: lowercaseMessage, code: code) {
          print("Valid code in message context.")
          return ParsedOTP(service: service, code: code.withNonDigitsRemoved ?? code)
        } else {
          print("Invalid context for code: \(code)")
        }
      }
    }

    print("No OTP detected.")

    let matchedParser = CUSTOM_PARSERS.first { parser in
      if let requiredName = parser.requiredServiceName, requiredName != service {
        return false
      }

      guard parser.canParseMessage(message), parser.parseMessage(message) != nil else { return false }

      return true
    }

    if let matchedParser = matchedParser, let parsedCode = matchedParser.parseMessage(message) {
      return parsedCode
    }

    return nil
  }

  private func isValidCodeInMessageContext(message: String, code: String) -> Bool {
    // Ensure the code is not empty as a basic validity check.
    guard !code.isEmpty else {
        print("Code is empty.")
        return false
    }

    // Attempt to find the range of the code within the message.
    if let codeRange = message.range(of: code) {
        var prevChar: Character?
        var nextChar: Character?

        // If there's a character before the code, capture it for context analysis.
        if codeRange.lowerBound > message.startIndex {
            let prevIndex = message.index(before: codeRange.lowerBound)
            prevChar = message[prevIndex]
        }

        // If there's a character after the code, capture it for context analysis.
        if codeRange.upperBound < message.endIndex {
            let nextIndex = message.index(after: codeRange.upperBound)
            nextChar = message[nextIndex]
        }

        print("Prev Char: \(String(describing: prevChar)), Next Char: \(String(describing: nextChar))")

        // If the code is at the start of the message or immediately follows a newline,
        // it's considered valid without further context checks.
        if prevChar == nil || prevChar == "\n" {
            print("Code is at the start of the message or after a newline, considered valid.")
            return true
        }

        // Check if the preceding character is invalid for a code context.
        // Codes should not immediately follow certain characters to be considered valid.
        if let prevChar = prevChar, prevChar != "-" {
            let isInvalidPrevChar = prevChar == "/" || prevChar == "\\" || prevChar == "$"
            if isInvalidPrevChar {
                print("Invalid preceding character for code: \(code)")
                return false
            }
        }

        // Validate the character following the code to ensure it's not part of another number or code.
        // This check allows for a broader range of valid separators after the code.
        if let nextChar = nextChar, !OTPParserConstants.endingCharacters.contains(nextChar) {
            if nextChar.isNumber {
                print("Next character is a digit, invalid context for code: \(code)")
                return false
            }
            // If the next character is not a digit, it's considered a valid separator,
            // making the code contextually valid.
            print("Next character is not a digit, considered a valid separator for code: \(code)")
            return true
        }

        // If none of the above conditions are met, the code is considered valid based on its context.
        print("Code \(code) is considered valid based on context.")
        return true
    } else {
        // If the code cannot be found within the message, it's considered invalid.
        print("Code \(code) not found in message.")
        return false
    }
  }

  private func inferServiceFromMessage(_ message: String) -> String? {
    let lowercaseMessage = message.lowercased()
    for servicePattern in config.servicePatterns {
      guard let possibleServiceName = servicePattern.firstCaptureGroupInString(lowercaseMessage),
            !possibleServiceName.isEmpty,
            !OTPParserConstants.authWords.contains(possibleServiceName) else {
        continue
      }

      return possibleServiceName
    }

    for knownService in config.knownServices {
      if lowercaseMessage.contains(knownService) {
        return knownService
      }
    }

    return nil
  }
}
