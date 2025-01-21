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


import unittest

# from parsing import parse_ports_string, protocols_to_numbers
from policyanalyzer import Action


class TestAction(unittest.TestCase):
    def test_get_action_valid_permit(self):
        """Test if get_action correctly identifies permit actions."""
        for action_str in ["PERMIT", "ALLOW", "ACCEPT", "PASS"]:
            action = Action.get_action(action_str)
            self.assertTrue(action.action)
            self.assertEqual(repr(action), "ACCEPT")

    def test_get_action_valid_deny(self):
        """Test if get_action correctly identifies deny actions."""
        for action_str in ["DENY", "REJECT", "DROP"]:
            action = Action.get_action(action_str)
            self.assertFalse(action.action)
            self.assertEqual(repr(action), "DENY")

    def test_get_action_invalid_string(self):
        """Test if get_action raises ValueError for invalid strings."""
        with self.assertRaises(ValueError):
            Action.get_action("INVALID")

    def test_get_action_case_insensitivity(self):
        """Test if get_action is case-insensitive."""
        action_permit = Action.get_action("permit")
        self.assertTrue(action_permit.action)
        self.assertEqual(repr(action_permit), "ACCEPT")

        action_deny = Action.get_action("deny")
        self.assertFalse(action_deny.action)
        self.assertEqual(repr(action_deny), "DENY")

    def test_get_action_non_string_input(self):
        """Test if get_action raises ValueError for non-string inputs."""
        with self.assertRaises(ValueError):
            Action.get_action(123)

        with self.assertRaises(ValueError):
            Action.get_action(None)

    def test_equality(self):
        """Test if equality operator works correctly."""
        action1 = Action.get_action("PERMIT")
        action2 = Action.get_action("ALLOW")
        action3 = Action.get_action("DENY")

        self.assertEqual(action1, action2)
        self.assertNotEqual(action1, action3)


if __name__ == "__main__":
    unittest.main()
