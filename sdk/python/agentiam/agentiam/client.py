import requests
from typing import Dict, Optional

class AgentIAMClient:
    """
    Client for interacting with the AgentIAM Control Plane API.
    """
    
    def __init__(self, base_url: str = "http://localhost:9090", timeout: int = 5):
        self.base_url = base_url.rstrip("/")
        self.timeout = timeout
        
    def generate_credentials(self, agent_id: str) -> Dict[str, str]:
        """
        Dynamically provisions an ephemeral credential for an agent.
        
        Args:
            agent_id: A unique identifier for the agent (e.g. 'langchain_bot')
            
        Returns:
            Dict containing 'agent_id' and 'password'
        """
        resp = requests.post(
            f"{self.base_url}/api/credentials",
            json={"agent_id": agent_id},
            timeout=self.timeout
        )
        resp.raise_for_status()
        return resp.json()
        
    def get_connection_string(self, agent_id: str, db_name: str, host: str = "localhost", port: int = 5432) -> str:
        """
        Provisions a credential and returns a fully formed SQLAlchemy connection string.
        """
        creds = self.generate_credentials(agent_id)
        password = creds['password']
        # Use postgresql+psycopg2 as the default driver since AgentIAM speaks Postgres protocol
        return f"postgresql+psycopg2://{agent_id}:{password}@{host}:{port}/{db_name}"
