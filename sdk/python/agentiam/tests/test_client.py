import unittest
from unittest.mock import patch, Mock
from agentiam.client import AgentIAMClient

class TestAgentIAMClient(unittest.TestCase):
    
    @patch('requests.post')
    def test_generate_credentials(self, mock_post):
        # Mock the HTTP response from the proxy
        mock_response = Mock()
        mock_response.json.return_value = {
            "agent_id": "test_agent",
            "password": "test_password_123"
        }
        mock_post.return_value = mock_response
        
        client = AgentIAMClient(base_url="http://test:9090")
        creds = client.generate_credentials("test_agent")
        
        self.assertEqual(creds["agent_id"], "test_agent")
        self.assertEqual(creds["password"], "test_password_123")
        mock_post.assert_called_once_with(
            "http://test:9090/api/credentials",
            json={"agent_id": "test_agent"},
            timeout=5
        )
        
    @patch('agentiam.client.AgentIAMClient.generate_credentials')
    def test_get_connection_string(self, mock_generate):
        mock_generate.return_value = {
            "agent_id": "test_agent",
            "password": "super_secret_password"
        }
        
        client = AgentIAMClient(base_url="http://test:9090")
        conn_str = client.get_connection_string("test_agent", "my_db", host="127.0.0.1", port=5435)
        
        expected = "postgresql+psycopg2://test_agent:super_secret_password@127.0.0.1:5435/my_db"
        self.assertEqual(conn_str, expected)

if __name__ == '__main__':
    unittest.main()
