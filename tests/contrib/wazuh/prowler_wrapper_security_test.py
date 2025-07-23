#!/usr/bin/env python
"""
Security test for prowler-wrapper.py command injection vulnerability
This test demonstrates the command injection vulnerability and validates the fix
"""

import os
import subprocess
import sys
import tempfile
import shutil
import unittest
from unittest.mock import patch, MagicMock, call


class TestProwlerWrapperSecurity(unittest.TestCase):
    """Test cases for command injection vulnerability in prowler-wrapper.py"""
    
    def setUp(self):
        """Set up test environment"""
        # Create a temporary directory for testing
        self.test_dir = tempfile.mkdtemp()
        self.prowler_wrapper_path = os.path.join(
            os.path.dirname(os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))), 
            'contrib', 'wazuh', 'prowler-wrapper.py'
        )
        
    def tearDown(self):
        """Clean up test environment"""
        shutil.rmtree(self.test_dir, ignore_errors=True)
        
    def _import_prowler_wrapper(self):
        """Helper to import prowler_wrapper with mocked WAZUH_PATH"""
        sys.path.insert(0, os.path.dirname(self.prowler_wrapper_path))
        
        # Mock the WAZUH_PATH that's read at module level
        with patch('builtins.open', create=True) as mock_open:
            mock_open.return_value.readline.return_value = 'DIRECTORY="/opt/wazuh"'
            
            import importlib.util
            spec = importlib.util.spec_from_file_location("prowler_wrapper", self.prowler_wrapper_path)
            prowler_wrapper = importlib.util.module_from_spec(spec)
            spec.loader.exec_module(prowler_wrapper)
            return prowler_wrapper._run_prowler
        
    def test_command_injection_semicolon(self):
        """Test command injection using semicolon"""
        # Create a test file that should not be created if injection is prevented
        test_file = os.path.join(self.test_dir, 'pwned.txt')
        
        # Malicious profile that attempts to create a file
        malicious_profile = f'test; touch {test_file}'
        
        # Mock the subprocess.Popen to capture the command
        with patch('subprocess.Popen') as mock_popen:
            mock_process = MagicMock()
            mock_process.communicate.return_value = (b'test output', None)
            mock_popen.return_value = mock_process
            
            # Import and run the vulnerable function
            _run_prowler = self._import_prowler_wrapper()
            
            # Run with malicious input
            _run_prowler(f'-p "{malicious_profile}" -V')
            
            # Check that Popen was called
            self.assertTrue(mock_popen.called)
            
            # Get the actual command that was passed to Popen
            actual_command = mock_popen.call_args[0][0]
            
            # With the fix, the command should be a list (from shlex.split)
            # and should NOT have shell=True
            self.assertIsInstance(actual_command, list, 
                "Command should be a list after shlex.split")
            
            # Check that shell=True is not in the call
            call_kwargs = mock_popen.call_args[1]
            self.assertNotIn('shell', call_kwargs, 
                "shell parameter should not be present (defaults to False)")
            
    def test_command_injection_ampersand(self):
        """Test command injection using ampersand"""
        # Create a test file that should not be created if injection is prevented
        test_file = os.path.join(self.test_dir, 'pwned2.txt')
        
        # Malicious profile that attempts to create a file
        malicious_profile = f'test && touch {test_file}'
        
        with patch('subprocess.Popen') as mock_popen:
            mock_process = MagicMock()
            mock_process.communicate.return_value = (b'test output', None)
            mock_popen.return_value = mock_process
            
            # Import and run the function
            _run_prowler = self._import_prowler_wrapper()
            
            # Run with malicious input
            _run_prowler(f'-p "{malicious_profile}" -V')
            
            # Get the actual command
            actual_command = mock_popen.call_args[0][0]
            
            # Verify it's a list (safe execution)
            self.assertIsInstance(actual_command, list)
            
            # The malicious characters should be preserved as part of the argument
            # not interpreted as shell commands
            command_str = ' '.join(actual_command)
            self.assertIn('&&', command_str, 
                "Shell metacharacters should be preserved as literals")
            
    def test_command_injection_pipe(self):
        """Test command injection using pipe"""
        malicious_profile = 'test | echo "injected"'
        
        with patch('subprocess.Popen') as mock_popen:
            mock_process = MagicMock()
            mock_process.communicate.return_value = (b'test output', None)
            mock_popen.return_value = mock_process
            
            # Import and run the function
            _run_prowler = self._import_prowler_wrapper()
            
            # Run with malicious input
            _run_prowler(f'-p "{malicious_profile}" -V')
            
            # Get the actual command
            actual_command = mock_popen.call_args[0][0]
            
            # Verify safe execution
            self.assertIsInstance(actual_command, list)
            
            # Pipe should be preserved as literal
            command_str = ' '.join(actual_command)
            self.assertIn('|', command_str)
            
    def test_command_injection_backticks(self):
        """Test command injection using backticks"""
        malicious_profile = 'test `echo injected`'
        
        with patch('subprocess.Popen') as mock_popen:
            mock_process = MagicMock()
            mock_process.communicate.return_value = (b'test output', None)
            mock_popen.return_value = mock_process
            
            # Import and run the function
            _run_prowler = self._import_prowler_wrapper()
            
            # Run with malicious input  
            _run_prowler(f'-p "{malicious_profile}" -V')
            
            # Get the actual command
            actual_command = mock_popen.call_args[0][0]
            
            # Verify safe execution
            self.assertIsInstance(actual_command, list)
            
            # Backticks should be preserved as literals
            command_str = ' '.join(actual_command)
            self.assertIn('`', command_str)
            
    def test_command_injection_dollar_parentheses(self):
        """Test command injection using $() syntax"""
        malicious_profile = 'test $(echo injected)'
        
        with patch('subprocess.Popen') as mock_popen:
            mock_process = MagicMock()
            mock_process.communicate.return_value = (b'test output', None)
            mock_popen.return_value = mock_process
            
            # Import and run the function
            _run_prowler = self._import_prowler_wrapper()
            
            # Run with malicious input
            _run_prowler(f'-p "{malicious_profile}" -V')
            
            # Get the actual command
            actual_command = mock_popen.call_args[0][0]
            
            # Verify safe execution
            self.assertIsInstance(actual_command, list)
            
            # $() should be preserved as literals
            command_str = ' '.join(actual_command)
            self.assertIn('$(', command_str)
            
    def test_legitimate_profile_name(self):
        """Test that legitimate profile names still work correctly"""
        legitimate_profile = 'production-aws-profile'
        
        with patch('subprocess.Popen') as mock_popen:
            mock_process = MagicMock()
            mock_process.communicate.return_value = (b'test output', None)
            mock_popen.return_value = mock_process
            
            # Import and run the function
            _run_prowler = self._import_prowler_wrapper()
            
            # Run with legitimate input
            result = _run_prowler(f'-p {legitimate_profile} -V')
            
            # Verify the function returns output
            self.assertEqual(result, b'test output')
            
            # Verify Popen was called correctly
            actual_command = mock_popen.call_args[0][0]
            self.assertIsInstance(actual_command, list)
            
            # Check the profile is passed correctly
            command_str = ' '.join(actual_command)
            self.assertIn(legitimate_profile, command_str)
            
    def test_shlex_split_behavior(self):
        """Test that shlex properly handles quoted arguments"""
        profile_with_spaces = 'my profile name'
        
        with patch('subprocess.Popen') as mock_popen:
            mock_process = MagicMock()
            mock_process.communicate.return_value = (b'test output', None)
            mock_popen.return_value = mock_process
            
            # Import and run the function
            _run_prowler = self._import_prowler_wrapper()
            
            # Run with profile containing spaces
            _run_prowler(f'-p "{profile_with_spaces}" -V')
            
            # Get the actual command
            actual_command = mock_popen.call_args[0][0]
            
            # Verify it's properly split
            self.assertIsInstance(actual_command, list)
            
            # The profile name should be preserved as a single argument
            # despite containing spaces
            self.assertIn('my profile name', actual_command)


if __name__ == '__main__':
    unittest.main()