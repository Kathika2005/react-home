import re

def detect_buffer_overflow(cpp_code):
    overflow_pattern = re.compile(r'buffer\[\d+\]')  # Detects buffer access by index
    # Look for instances where an index is out of bounds
    overflow_matches = re.findall(overflow_pattern, cpp_code)

    if overflow_matches:
        for match in overflow_matches:
            # Check for overflow/underflow indications
            index = int(re.search(r'\d+', match).group())
            if index >= 10 or index < 0:  # Assuming buffer size of 10
                print(f"Buffer access out of bounds detected: {match}")

    # Check for use of negative indices, which would be an underflow
    underflow_pattern = re.compile(r'buffer\[-\d+\]')
    underflow_matches = re.findall(underflow_pattern, cpp_code)

    if underflow_matches:
        for match in underflow_matches:
            print(f"Buffer underflow detected: {match}")

    if not (overflow_matches or underflow_matches):
        print("No buffer overflow/underflow detected.")

# Sample vulnerable C++ code
cpp_code = """
#include <iostream>

int main() {
    char buffer[10];  // A buffer of 10 characters

    // Filling the buffer with user input
    std::cout << "Enter a string: ";
    std::cin >> buffer;

    // Accessing memory past the buffer's bounds
    std::cout << "You entered: " << buffer << std::endl;
    std::cout << "Buffer overflow: " << buffer[15] << std::endl;  // This is out of bounds

    // Attempt to access data before the start of the buffer (negative index)
    std::cout << "Buffer underflow: " << buffer[-1] << std::endl;  // This is before the buffer

    return 0;
}
"""

# Run the vulnerability detection
detect_buffer_overflow(cpp_code)
