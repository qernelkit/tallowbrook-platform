import SwiftUI

/// Card number input: groups digits in fours as the customer types and checks the
/// number before the pay button is enabled.
struct CardNumberField: View {
    @Binding var number: String
    @Binding var isValid: Bool

    var body: some View {
        TextField("Card number", text: $number)
            .keyboardType(.numberPad)
            .textContentType(.creditCardNumber)
            .font(.body.monospacedDigit())
            .onChange(of: number) { _, newValue in
                let formatted = Self.format(newValue)
                if formatted != newValue {
                    number = formatted
                }
                isValid = Self.isPlausible(formatted)
            }
    }

    static func digits(of text: String) -> [Int] {
        text.compactMap { $0.wholeNumberValue }
    }

    static func format(_ text: String) -> String {
        let digits = Self.digits(of: text).prefix(19)
        var result = ""
        for (index, digit) in digits.enumerated() {
            if index > 0 && index.isMultiple(of: 4) {
                result.append(" ")
            }
            result.append(String(digit))
        }
        return result
    }

    static func isPlausible(_ text: String) -> Bool {
        let digits = Self.digits(of: text)
        return (13...19).contains(digits.count) && passesLuhnCheck(digits)
    }

    static func passesLuhnCheck(_ digits: [Int]) -> Bool {
        var sum = 0
        for (offset, digit) in digits.reversed().enumerated() {
            if offset.isMultiple(of: 2) {
                sum += digit
            } else {
                let doubled = digit * 2
                sum += doubled > 9 ? doubled - 9 : doubled
            }
        }
        return sum.isMultiple(of: 10)
    }
}
