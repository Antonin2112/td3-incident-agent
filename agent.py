from deepagents import create_deep_agent
from deepagents.backends import FilesystemBackend
from langchain_ollama import ChatOllama

agent = create_deep_agent(
    model=ChatOllama(model="nemotron-3-nano:30b-cloud", temperature=0),
    system_prompt="You are a SOC analyst.",
    backend=FilesystemBackend(root_dir=".", virtual_mode=True),
)

answer = agent.invoke({
    "messages": [
        {"role": "user", "content": "Handle the ticket /incident/ticket_INC-2026-0417.md"}
    ]
})

print(answer["messages"][-1].content)
