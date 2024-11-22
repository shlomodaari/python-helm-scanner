
# Python Helm Vulnerability Scanner

This Python application automates the process of pulling a Helm chart from a repository, extracting the chart, rendering it, and scanning the images within the chart for vulnerabilities using the Grype scanner. The application also provides functionality for adding Helm repositories, pulling charts, and parsing their output for image vulnerabilities.

## Features

- Add a Helm repository.
- Pull a Helm chart from the repository.
- Extract Helm chart files.
- Render Helm chart templates.
- Parse Helm chart to identify image vulnerabilities.
- Run vulnerability scans on Docker images using Grype.
- Save the results of the vulnerability scan into a CSV file.

## Prerequisites

Ensure you have the following tools installed before running the application:

- [Python 3](https://www.python.org/downloads/)
- [Helm](https://helm.sh/docs/intro/install/)
- [Grype](https://github.com/anchore/grype)
- [Docker](https://www.docker.com/products/docker-desktop)

Additionally, ensure the following Python dependencies are installed:

```bash
pip install pyyaml
pip install subprocess
pip install tarfile
```

## Usage

### Step 1: Clone the Repository

Clone this repository to your local machine:

```bash
git clone https://github.com/yourusername/python-helm-scanner.git
cd python-helm-scanner
```

### Step 2: Run the Application

Execute the application by running the Python script:

```bash
python helm_scanner.py
```

The script will prompt you to enter the following inputs:

- **Helm Repository Name:** The name of the Helm repository (e.g., `ingress-nginx`).
- **Helm Repository URL:** The URL of the Helm repository (e.g., `https://kubernetes.github.io/ingress-nginx`).
- **Helm Chart Name:** The name of the Helm chart (e.g., `ingress-nginx`).
- **Helm Chart Version:** The version of the chart to scan (e.g., `4.11.3`).

### Step 3: Vulnerability Scan

Once the script pulls and renders the Helm chart, it will extract all image names and perform a vulnerability scan on them using the **Grype** scanner. After the scan, the results will be saved to a CSV file (e.g., `2024-11-21_vulnerability_scan_results.csv`).

### Step 4: View the Scan Results

The results of the vulnerability scan will be saved in a CSV file named after the current date and time. You can open the CSV file to review the vulnerabilities detected in the images used by the Helm chart.

## Docker Image

You can download and run this application as a Docker container. The Docker image is hosted on Docker Hub:

**Image Name:** `shlomodaari1992/python-helm-scanner`

### Step 1: Pull the Docker Image

Run the following command to pull the Docker image from Docker Hub:

```bash
docker pull shlomodaari1992/python-helm-scanner
```

### Step 2: Run the Docker Image

After the image is pulled, you can run the container using the following command:

```bash
docker run -it --rm shlomodaari1992/python-helm-scanner
```

This will run the same Python application inside the container. The application will still prompt you for Helm repository and chart details, just as if you were running it locally.

## How it Works

### 1. Add Helm Repository

The application adds the specified Helm repository using `helm repo add` and updates the repository with `helm repo update`.

### 2. Pull the Helm Chart

It pulls the specified version of the Helm chart using the `helm pull` command.

### 3. Extract the Helm Chart

The chart is extracted from the `.tgz` file to the working directory using the `tarfile` module.

### 4. Render Helm Chart

The Helm chart templates are rendered to resolve any placeholders (using `helm template`).

### 5. Image Parsing

The application parses the rendered output for any Docker image references and extracts the image names and tags.

### 6. Run Vulnerability Scan

The images are scanned using Grype (or another scanner if specified) for known vulnerabilities. The scan results are saved in a CSV file for easy analysis.

### 7. Clean Up

Temporary files and directories are removed after the scan is complete.

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## Customization

You can customize the application to work with different vulnerability scanners (e.g., Trivy). To do this, modify the `run_vulnerability_scan()` function to support additional scanners.

## Example CSV Output

After running the vulnerability scan, the output is saved in a CSV file with the following format:

```csv
image_name,tag,vulnerability_name,severity,description
nginx,1.21.1,CVE-2021-1234,High,Description of vulnerability
nginx,1.21.1,CVE-2021-5678,Low,Description of vulnerability
```

This CSV file will help you easily identify which images have vulnerabilities and what their severity is.

---

**Note:** The application can be further extended to support more Helm chart configurations, different vulnerability scanning tools, and integration into continuous integration pipelines.
