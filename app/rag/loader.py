from langchain_text_splitters import MarkdownTextSplitter
from langchain_community.document_loaders import DirectoryLoader, TextLoader
from pathlib import Path
from langchain_core.documents import Document
import glob
import os

KNOWLEDGE_BASE_PATH = Path(__file__).parent.parent.parent / "data/knowledge_base"


class Loader():
    """This class is responsible for loading data from the knowledge base to be used for chunking and embeddings"""

    

    def fetch_documents_langchain(self) -> list[Document]:
        folders = glob.glob(str(Path(KNOWLEDGE_BASE_PATH) / "*"))
        print(str(Path(KNOWLEDGE_BASE_PATH) / "*"))
        documents: list[Document] = []
        for folder in folders:
            doc_type = os.path.basename(folder)
            loader = DirectoryLoader(
                folder, glob="**/*.md", loader_cls=TextLoader, loader_kwargs={"encoding": "utf-8"}
            )
            folder_docs = loader.load()
            for doc in folder_docs:
                source_path = doc.metadata.get("source")
                file_name = Path(source_path).name if source_path else ""
                file_name_without_extension = Path(source_path).stem if source_path else ""

                doc.metadata["category"] = doc_type
                doc.metadata["document"] = file_name
                doc.metadata["data_source"] = "project_knowledge"
                if doc_type == 'security':
                    doc.metadata["incident_type"] = None if file_name_without_extension == 'indicators_of_compromise' else file_name_without_extension
                documents.append(doc)
        return documents


