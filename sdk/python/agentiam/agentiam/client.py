import os
import httpx
from typing import Dict, Optional

class AgentIAMClient:
    """
    Synchronous Client for interacting with the AgentIAM Control Plane API.
    """
    
    def __init__(self, base_url: Optional[str] = None, timeout: int = 5):
        # Fallback priority: explicit base_url -> AGENTIAM_URL -> default localhost:9090
        if base_url is None:
            base_url = os.getenv("AGENTIAM_URL", "http://localhost:9090")
        self.base_url = base_url.rstrip("/")
        self.timeout = timeout
        
    def generate_credentials(self, agent_id: str, ttl_seconds: int = 3600) -> Dict[str, str]:
        """
        Dynamically provisions an ephemeral credential for an agent.
        
        Args:
            agent_id: A unique identifier for the agent (e.g. 'langchain_bot')
            ttl_seconds: How long the credential is valid for (default 1 hour).
            
        Returns:
            Dict containing 'agent_id', 'password', and 'ttl_seconds'
        """
        with httpx.Client(timeout=self.timeout) as client:
            resp = client.post(
                f"{self.base_url}/api/credentials",
                json={"agent_id": agent_id, "ttl_seconds": ttl_seconds}
            )
            resp.raise_for_status()
            return resp.json()
        
    def get_connection_string(self, agent_id: str, db_name: str, host: str = "localhost", port: int = 5432, ttl_seconds: int = 3600) -> str:
        """
        Provisions a credential and returns a fully formed SQLAlchemy connection string.
        """
        creds = self.generate_credentials(agent_id, ttl_seconds)
        password = creds['password']
        return f"postgresql+psycopg2://{agent_id}:{password}@{host}:{port}/{db_name}"


class AsyncAgentIAMClient:
    """
    Asynchronous Client for interacting with the AgentIAM Control Plane API.
    """
    
    def __init__(self, base_url: Optional[str] = None, timeout: int = 5):
        if base_url is None:
            base_url = os.getenv("AGENTIAM_URL", "http://localhost:9090")
        self.base_url = base_url.rstrip("/")
        self.timeout = timeout
        
    async def generate_credentials(self, agent_id: str, ttl_seconds: int = 3600) -> Dict[str, str]:
        async with httpx.AsyncClient(timeout=self.timeout) as client:
            resp = await client.post(
                f"{self.base_url}/api/credentials",
                json={"agent_id": agent_id, "ttl_seconds": ttl_seconds}
            )
            resp.raise_for_status()
            return resp.json()
            
    async def get_connection_string(self, agent_id: str, db_name: str, host: str = "localhost", port: int = 5432, ttl_seconds: int = 3600) -> str:
        creds = await self.generate_credentials(agent_id, ttl_seconds)
        password = creds['password']
        return f"postgresql+psycopg2://{agent_id}:{password}@{host}:{port}/{db_name}"
