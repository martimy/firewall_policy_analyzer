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

if __name__ == "__main__":
    # Discover and run all tests in the "tests" directory
    test_loader = unittest.TestLoader()
    test_suite = test_loader.discover(start_dir="tests", pattern="us_*.py")

    test_runner = unittest.TextTestRunner(verbosity=2)
    test_runner.run(test_suite)
