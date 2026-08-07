from typing import Optional
from .client import AgentIAMClient

try:
    from langchain_community.utilities import SQLDatabase
except ImportError:
    SQLDatabase = None

def create_langchain_db(
    client: AgentIAMClient,
    agent_id: str,
    db_name: str,
    host: str = "localhost",
    port: int = 5432,
    **kwargs
) -> "SQLDatabase":
    """
    Automatically provisions an AgentIAM credential and returns a LangChain SQLDatabase.
    
    Args:
        client: An initialized AgentIAMClient instance.
        agent_id: The unique identifier for your AI agent.
        db_name: The name of the database to connect to.
        host: The host where the AgentIAM proxy is running.
        port: The port where the AgentIAM proxy is listening.
        **kwargs: Additional arguments to pass to SQLDatabase.from_uri()
        
    Returns:
        SQLDatabase: A LangChain SQLDatabase instance connected via the proxy.
    """
    if SQLDatabase is None:
        raise ImportError(
            "LangChain is not installed. Please install it using: pip install agentiam[langchain]"
        )
        
    connection_uri = client.get_connection_string(agent_id, db_name, host, port)
    return SQLDatabase.from_uri(connection_uri, **kwargs)
