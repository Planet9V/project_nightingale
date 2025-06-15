# Jina AI + Pinecone Integration Guide

## Overview
This comprehensive guide covers the integration of Jina AI's embedding models with Pinecone vector database for Project Seldon's ETL pipeline.

## Table of Contents
1. [Jina Embedding Models](#jina-embedding-models)
2. [Pinecone Configuration](#pinecone-configuration)
3. [API Authentication & Rate Limits](#api-authentication--rate-limits)
4. [Implementation Guide](#implementation-guide)
5. [Jina AI Services Suite](#jina-ai-services-suite)
6. [Cost Optimization](#cost-optimization)
7. [Best Practices](#best-practices)

## Jina Embedding Models

### jina-embeddings-v2-base-en
- **Dimensions**: 768
- **Max Input Tokens**: 8,192
- **Metric**: Cosine similarity
- **Best For**: Text embeddings with short queries returning large passages
- **Languages**: English optimized

### jina-embeddings-v3
- **Dimensions**: 1024 (adjustable via Matryoshka)
- **Max Input Tokens**: 8,192
- **Languages**: 89 languages supported
- **Features**: Task-specific embeddings

### jina-clip-v2 (Multimodal)
- **Default Dimensions**: 1024 (can truncate to 768 or 64)
- **Image Resolution**: 512×512 pixels
- **Languages**: 89 languages for text
- **Architecture**: 
  - Text Encoder: Jina XLM-RoBERTa (561M parameters)
  - Vision Encoder: EVA02-L14 (304M parameters)
- **Features**: Text-text, text-image, image-image, image-text retrieval

## Pinecone Configuration

### Creating Index for Jina Embeddings

```python
import pinecone
from pinecone import Pinecone, ServerlessSpec

# Initialize Pinecone
pc = Pinecone(api_key="YOUR_PINECONE_API_KEY")

# Create index for jina-embeddings-v2-base-en
pc.create_index(
    name="nightingale",
    dimension=768,  # For jina-embeddings-v2-base-en
    metric="cosine",
    spec=ServerlessSpec(
        cloud="aws",
        region="us-east-1"
    )
)

# For jina-clip-v2 with 768 dimensions
pc.create_index(
    name="nightingale-clip",
    dimension=768,  # Truncated from 1024
    metric="cosine",
    spec=ServerlessSpec(
        cloud="aws",
        region="us-east-1"
    )
)
```

## API Authentication & Rate Limits

### Authentication
```bash
# Set API key
export JINA_API_KEY="jina_xxxxxxxxxxxxxxxxxxxx"
```

### Rate Limits
| Tier | Embeddings | Reranker | Classifier | Reader |
|------|------------|----------|------------|---------|
| Free (no key) | 500 RPM | 500 RPM | 20 RPM | 20 RPM |
| Free (with key) | 2,000 RPM | 2,000 RPM | 60 RPM | 200 RPM |
| Premium | 10,000 RPM | 10,000 RPM | 500 RPM | 1,000 RPM |
| Token Limits | 1M-5M TPM | 1M-5M TPM | 300K TPM | Varies |

### Pricing
- **Free Tier**: 10 million tokens upon signup
- **jina-clip-v2 Images**: 4,000 tokens per 512×512 tile
- **Text**: Standard tokenization (~0.75 tokens per word)
- **Cost**: $0.02 USD per 1M tokens

## Implementation Guide

### 1. Basic Text Embedding with jina-embeddings-v2

```python
import requests
import numpy as np
from typing import List, Dict

class JinaEmbedder:
    def __init__(self, api_key: str):
        self.api_key = api_key
        self.endpoint = "https://api.jina.ai/v1/embeddings"
        
    def embed_texts(self, texts: List[str], model: str = "jina-embeddings-v2-base-en") -> List[List[float]]:
        """Generate embeddings for text using Jina API"""
        
        response = requests.post(
            self.endpoint,
            headers={
                "Authorization": f"Bearer {self.api_key}",
                "Content-Type": "application/json"
            },
            json={
                "model": model,
                "input": texts,
                "encoding_type": "float"
            }
        )
        
        if response.status_code == 200:
            data = response.json()
            return [item["embedding"] for item in data["data"]]
        else:
            raise Exception(f"API Error: {response.status_code} - {response.text}")
```

### 2. Multimodal Embedding with jina-clip-v2

```python
class JinaClipEmbedder:
    def __init__(self, api_key: str):
        self.api_key = api_key
        self.endpoint = "https://api.jina.ai/v1/embeddings"
        
    def embed_multimodal(self, inputs: List[Dict]) -> List[List[float]]:
        """
        Generate embeddings for mixed text and images
        
        inputs: List of dicts with either {"text": "..."} or {"image": "url/base64"}
        """
        
        response = requests.post(
            self.endpoint,
            headers={
                "Authorization": f"Bearer {self.api_key}",
                "Content-Type": "application/json"
            },
            json={
                "model": "jina-clip-v2",
                "input": inputs,
                "dimensions": 768  # Truncate to 768 for Pinecone
            }
        )
        
        if response.status_code == 200:
            data = response.json()
            return [item["embedding"] for item in data["data"]]
        else:
            raise Exception(f"API Error: {response.status_code} - {response.text}")

# Example usage
embedder = JinaClipEmbedder(api_key="your_key")

# Mixed inputs
inputs = [
    {"text": "Critical infrastructure cybersecurity"},
    {"image": "https://example.com/scada-system.jpg"},
    {"text": "Dragos OT security platform"}
]

embeddings = embedder.embed_multimodal(inputs)
```

### 3. Pinecone Integration

```python
from pinecone import Pinecone
import uuid

class PineconeVectorStore:
    def __init__(self, api_key: str, index_name: str):
        self.pc = Pinecone(api_key=api_key)
        self.index = self.pc.Index(index_name)
        
    def upsert_embeddings(self, embeddings: List[List[float]], 
                         texts: List[str], metadata: List[Dict]):
        """Store embeddings in Pinecone with metadata"""
        
        vectors = []
        for i, (embedding, text, meta) in enumerate(zip(embeddings, texts, metadata)):
            vectors.append({
                "id": str(uuid.uuid4()),
                "values": embedding,
                "metadata": {
                    "text": text[:1000],  # Pinecone metadata limit
                    **meta
                }
            })
        
        # Batch upsert
        batch_size = 100
        for i in range(0, len(vectors), batch_size):
            batch = vectors[i:i + batch_size]
            self.index.upsert(vectors=batch)
            
    def search(self, query_embedding: List[float], top_k: int = 10):
        """Search for similar vectors"""
        
        results = self.index.query(
            vector=query_embedding,
            top_k=top_k,
            include_values=False,
            include_metadata=True
        )
        
        return results.matches
```

## Jina AI Services Suite

### 1. Reader API
- **Purpose**: Convert web pages to LLM-friendly text
- **Endpoint**: `https://r.jina.ai/[URL]`
- **Features**:
  - PDF support
  - Shadow DOM & iframe extraction
  - Locale control
  - Stream mode for large pages
- **Rate Limits**: 20 RPM (free), 200 RPM (with key)
- **Cost**: $0.02 per 1M tokens

### 2. Reranker API
- **Endpoint**: `https://api.jina.ai/v1/rerank`
- **Models**: 
  - jina-reranker-v1-base-en
  - jina-reranker-v2-base-multilingual
- **Use Case**: Improve search relevance by reordering results

```python
def rerank_results(query: str, documents: List[str], api_key: str):
    response = requests.post(
        "https://api.jina.ai/v1/rerank",
        headers={"Authorization": f"Bearer {api_key}"},
        json={
            "model": "jina-reranker-v2-base-multilingual",
            "query": query,
            "documents": documents,
            "top_n": 10
        }
    )
    return response.json()["results"]
```

### 3. Classifier API
- **Endpoint**: `https://api.jina.ai/v1/classify`
- **Use Case**: Categorize documents before embedding
- **Rate Limit**: 60 RPM (free), 500 RPM (premium)

### 4. DeepSearch API
- **Endpoint**: `https://api.jina.ai/v1/search`
- **Features**: Advanced semantic search with context understanding
- **Rate Limit**: 500 RPM

## Cost Optimization

### 1. Image Processing
```python
# Resize images before processing to save tokens
from PIL import Image
import io
import base64

def optimize_image_for_jina(image_path: str) -> str:
    """Resize image to 512x512 to minimize token usage"""
    img = Image.open(image_path)
    img.thumbnail((512, 512), Image.Resampling.LANCZOS)
    
    buffer = io.BytesIO()
    img.save(buffer, format="PNG")
    img_base64 = base64.b64encode(buffer.getvalue()).decode()
    
    return f"data:image/png;base64,{img_base64}"
```

### 2. Batch Processing
```python
def batch_embed_with_rate_limit(texts: List[str], batch_size: int = 100):
    """Process in batches to stay within rate limits"""
    embeddings = []
    
    for i in range(0, len(texts), batch_size):
        batch = texts[i:i + batch_size]
        batch_embeddings = embedder.embed_texts(batch)
        embeddings.extend(batch_embeddings)
        
        # Rate limit compliance (2000 RPM = ~33 RPS)
        if i + batch_size < len(texts):
            time.sleep(3)  # ~20 requests per minute
            
    return embeddings
```

### 3. Dimension Reduction
```python
# Use Matryoshka representation to reduce dimensions
response = requests.post(
    "https://api.jina.ai/v1/embeddings",
    headers={"Authorization": f"Bearer {api_key}"},
    json={
        "model": "jina-clip-v2",
        "input": texts,
        "dimensions": 256  # Reduce from 1024 to 256
    }
)
```

## Best Practices

### 1. Error Handling
```python
import time
from typing import Optional

def embed_with_retry(texts: List[str], max_retries: int = 3) -> Optional[List[List[float]]]:
    """Embed with exponential backoff retry"""
    
    for attempt in range(max_retries):
        try:
            return embedder.embed_texts(texts)
        except Exception as e:
            if "402" in str(e):
                raise Exception("Payment required - check API key and billing")
            elif "429" in str(e):
                # Rate limit hit - exponential backoff
                wait_time = 2 ** attempt
                print(f"Rate limit hit, waiting {wait_time}s...")
                time.sleep(wait_time)
            else:
                if attempt == max_retries - 1:
                    raise
                time.sleep(1)
    
    return None
```

### 2. Monitoring Usage
```python
class JinaUsageTracker:
    def __init__(self):
        self.total_tokens = 0
        self.requests = 0
        
    def track_response(self, response_data: dict):
        """Track token usage from API response"""
        if "usage" in response_data:
            self.total_tokens += response_data["usage"]["total_tokens"]
            self.requests += 1
            
    def get_estimated_cost(self) -> float:
        """Calculate estimated cost at $0.02 per 1M tokens"""
        return (self.total_tokens / 1_000_000) * 0.02
```

### 3. Hybrid Search Implementation
```python
def hybrid_search(query: str, index: PineconeIndex, 
                  embedder: JinaEmbedder, reranker_key: str):
    """Combine embedding search with reranking"""
    
    # 1. Generate query embedding
    query_embedding = embedder.embed_texts([query])[0]
    
    # 2. Search Pinecone
    initial_results = index.query(
        vector=query_embedding,
        top_k=50,  # Get more candidates
        include_metadata=True
    )
    
    # 3. Extract texts for reranking
    candidate_texts = [match.metadata["text"] for match in initial_results.matches]
    
    # 4. Rerank results
    reranked = rerank_results(query, candidate_texts, reranker_key)
    
    # 5. Return top results
    return reranked[:10]
```

## Project Seldon Configuration

### Environment Variables (.env)
```bash
# Jina AI Configuration
JINA_API_KEY=jina_xxxxxxxxxxxxxxxxxxxx
JINA_MODEL=jina-clip-v2
JINA_EMBEDDING_ENDPOINT=https://api.jina.ai/v1/embeddings
JINA_RERANKING_ENDPOINT=https://api.jina.ai/v1/rerank
JINA_CLASSIFIER_ENDPOINT=https://api.jina.ai/v1/classify
JINA_DEEPSEARCH_ENDPOINT=https://api.jina.ai/v1/search
JINA_READER_ENDPOINT=https://r.jina.ai/

# Pinecone Configuration
PINECONE_API_KEY=pcsk_xxxxxxxxxxxxxxxxxxxx
PINECONE_INDEX_NAME=nightingale
PINECONE_ENVIRONMENT=us-east-1
EMBEDDING_DIMENSIONS=768
```

### TypeScript Interface
```typescript
interface JinaEmbeddingConfig {
  model: 'jina-embeddings-v2-base-en' | 'jina-embeddings-v3' | 'jina-clip-v2';
  dimensions: 768 | 1024;
  rateLimits: {
    embedding: 2000;  // RPM
    reranking: 2000;
    classifier: 60;
    deepSearch: 500;
  };
  batchSize: 100;
  maxRetries: 3;
  retryDelay: 1000;
}
```

## Troubleshooting

### Common Issues

1. **402 Payment Required**
   - Check API key is valid
   - Verify billing is active on Jina account
   - Ensure you haven't exceeded token limits

2. **Dimension Mismatch**
   - Ensure Pinecone index matches embedding dimensions
   - Use dimension parameter for jina-clip-v2 truncation

3. **Rate Limit Errors**
   - Implement exponential backoff
   - Reduce batch size
   - Add delays between requests

4. **Large Document Handling**
   ```python
   # Split large documents into chunks
   def chunk_text(text: str, max_tokens: int = 8000) -> List[str]:
       # Rough estimate: 1 token ≈ 4 characters
       max_chars = max_tokens * 4
       chunks = []
       
       for i in range(0, len(text), max_chars):
           chunks.append(text[i:i + max_chars])
           
       return chunks
   ```

## References
- [Jina Embeddings API](https://jina.ai/embeddings/)
- [Pinecone Jina Integration](https://docs.pinecone.io/integrations/jina)
- [Jina CLIP v2 Model](https://huggingface.co/jinaai/jina-clip-v2)
- [Jina Reader Documentation](https://github.com/jina-ai/reader)
- [API Dashboard](https://jina.ai/dashboard)

---

**Last Updated**: June 13, 2025  
**Author**: Project Seldon Team  
**Version**: 1.0