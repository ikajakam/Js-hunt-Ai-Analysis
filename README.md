
# JS Recon + AI Analysing Wrapper Script

  

This script fetches `.js` files from a target domain, analyse them for secrets, vulnerable code patterns and performs AI-based auditing using a local LLM model.

  

### Features

  

- Collects JS files using `subfinder` + `waybackurls`

- Downloads and stores JS files

- Extracts endpoints using **LinkFinder**

- Identifies secrets, tokens, and dangerous JS patterns

- Beautifies and verifies DOM sinks

- AI-based vulnerability analysis using `Qwen2.5-1.5B-Instruct`

- DOM tracer using Playwright

- GitHub dork generation

- CSP header check

- Burp / ZAP integration placeholder

  

### Prerequisites

  

- [subfinder](https://github.com/projectdiscovery/subfinder)

- [waybackurls](https://github.com/tomnomnom/waybackurls)

- [LinkFinder](https://github.com/GerbenJavado/LinkFinder)

  

### Python Libraries

  

Install required libraries using

```
pip install requests jsbeautifier halo tqdm torch transformers playwright
playwright install
```

  

### HuggingFace API Key

- Add this to your `.bashrc` or `.zshrc`

```
export HUGGINGFACE_API_KEY=hf_your_api_key_here
```

- reload your `.bashrc` or `.zshrc`
- models are cached in ~/.cache/huggingface
  

Note : This script uses model `Qwen/Qwen2.5-1.5B-Instruct` and runs it locally via CUDA

  

### Usage

```
python3 js4h.py --domain example.com
```

```
python3 js4h.py --domain example.com --proxy http://127.0.0.1:8080
```
- Results are saved in `jshunt_output/{domain}/`

####  Script halts after `js` files are downloaded, you can choose to continue Ai Analysis or do it later (as wild scope recon takes long time)

```
python3 jsh_updated.py --domain maashie.in --analysis jshunt_output/domain.com
```
