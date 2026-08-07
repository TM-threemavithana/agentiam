import os
from agentiam.client import AgentIAMClient
from agentiam.langchain import create_langchain_db

# Connect to the AgentIAM proxy control plane
# Note: Ensure the AgentIAM proxy is running natively via `./agentiam` or `make run`
client = AgentIAMClient(base_url="http://localhost:9090")

print("Provisioning ephemeral database credentials for 'sales_agent'...")
try:
    # This automatically asks the proxy to generate a temporary SCRAM password for 'sales_agent',
    # and returns a fully initialized LangChain SQLDatabase object.
    db = create_langchain_db(
        client=client,
        agent_id="sales_agent",
        db_name="postgres", # Use "mysql" if you are using the MySQL proxy port
        host="localhost",
        port=5432 # Proxy's downstream listener port
    )
    print("Successfully connected via AgentIAM proxy!")
    print(f"Dialect: {db.dialect}")
    
    # You can now pass this `db` object directly into LangChain's SQLDatabaseToolkit
    # For example:
    # from langchain_community.agent_toolkits import SQLDatabaseToolkit
    # from langchain_openai import ChatOpenAI
    # 
    # llm = ChatOpenAI(temperature=0)
    # toolkit = SQLDatabaseToolkit(db=db, llm=llm)
    # agent = create_sql_agent(llm=llm, toolkit=toolkit, verbose=True)
    # agent.run("How many users are in the system?")
    
except Exception as e:
    print(f"Failed to connect to AgentIAM proxy. Ensure the proxy is running on localhost:9090 and port 5432. Error: {e}")
