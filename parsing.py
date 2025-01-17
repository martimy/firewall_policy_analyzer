# -*- coding: utf-8 -*-

"""
Copyright 2025 Maen Artimy

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
"""

import re


def parse_ports_string(input_string):
    """
    Parse a string containing numbers, ranges, or keywords separated by commas into a set.
    Raises a ValueError if the format is invalid.
    """
    # Regular expression to match valid patterns: single numbers, ranges, or keywords
    pattern = r"^\s*([\w-]+)\s*(,\s*[\w-]+)*\s*$"

    if not re.match(pattern, input_string):
        raise ValueError(
            "Invalid format. Expected a comma-separated list of numbers, ranges, or keywords."
        )

    result_set = set()
    # Split the input by commas
    parts = input_string.split(",")

    for part in parts:
        part = part.strip()  # Remove extra whitespace
        if re.match(r"^\d+-\d+$", part):  # Detect range
            try:
                start, end = map(int, part.split("-"))
                if start > end:
                    raise ValueError(
                        f"Invalid range '{part}'. Start cannot be greater than end."
                    )
                # Add the range of numbers
                result_set.update(range(start, end + 1))
            except ValueError:
                raise ValueError(f"Invalid range format '{part}'.")
        elif re.match(r"^\d+$", part):  # Detect single number
            try:
                result_set.add(int(part))
            except ValueError:
                raise ValueError(f"Invalid number '{part}'.")
        elif re.match(r"^\w+$", part):  # Detect keywords
            result_set.add(part)
        else:
            raise ValueError(f"Invalid format for part '{part}'.")

    return result_set


def protocols_to_numbers(original_set, keyword_to_number_map):
    """
    Resolve keywords in the set to their corresponding numbers using the provided mapping.
    Returns a set of numbers or raises a ValueError if a keyword has no mapping.
    """
    resolved_set = set()

    for item in original_set:
        if isinstance(item, int):  # If it's already a number, add it to the result
            resolved_set.add(item)
        elif isinstance(item, str):  # If it's a keyword, resolve it
            if item in keyword_to_number_map:
                resolved_set.add(keyword_to_number_map[item])
            else:
                raise ValueError(
                    f"Keyword '{item}' does not have a corresponding number in the mapping."
                )
        else:
            raise ValueError(
                f"Unexpected item '{item}' in the set. Expected numbers or keywords."
            )

    if any(x <= 0 for x in resolved_set):
        raise ValueError("Invalid value of 0 or less.")

    return resolved_set


# Example usage
if __name__ == "__main__":

    mapping = {"UDP": 17, "TCP": 2}

    def read_and_parse_data(data):
        try:
            r = parse_ports_string(data)
            return protocols_to_numbers(r, mapping)
        except Exception as e:
            print(f"Error: {e}")

    data = "10,30-50,90,TCP,UDP,100-120"  # Replace with your file path
    result = read_and_parse_data(data)
    if result is not None:
        print("Parsed set of numbers and keywords:", result)
