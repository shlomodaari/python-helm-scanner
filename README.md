Python Helm Scanner
This is a Python application that helps you manage Helm charts, including adding Helm repositories, pulling charts, extracting chart files, rendering Helm templates, and scanning the Docker images used in the charts for vulnerabilities. The scanner supports tools like Grype and Trivy for vulnerability scanning and outputs the results in CSV format.

Features
Add Helm Repository: Adds a Helm repository to your local Helm configuration.
Pull Helm Chart: Downloads a specific version of a Helm chart.
Extract Helm Chart: Extracts a .tgz Helm chart file into a specified directory.
Render Helm Chart: Renders Helm chart templates to resolve placeholders.
Vulnerability Scan: Scans Docker images specified in the Helm chart using tools like Grype or Trivy.
Generate CSV Report: Outputs vulnerability scan results to a CSV file.
Requirements
Helm: The application uses Helm to manage Helm charts. You can install it from Helm's official website.
Docker: Used for running the application in a containerized environment. You can install it from Docker's official website.
Usage
1. Clone the Repository
First, clone this repository to your local machine:

bash
Copy code
git clone https://github.com/your-repository/python-helm-scanner.git
cd python-helm-scanner
2. Run the Application
The easiest way to run the application is through Docker. The application is packaged in a Docker image that you can pull and run.

Docker Image
You can download the Docker image from Docker Hub:

bash
Copy code
docker pull shlomodaari1992/python-helm-scanner
Running the Docker Container
Once the image is pulled, you can run the application by executing the following command:

bash
Copy code
docker run -it shlomodaari1992/python-helm-scanner
This will start the application and prompt you for the following inputs:

Helm repository name (e.g., ingress-nginx)
Helm repository URL (e.g., https://kubernetes.github.io/ingress-nginx)
Helm chart name (e.g., ingress-nginx)
Helm chart version (e.g., 4.11.3)
3. Running the Application Locally (Optional)
To run the application locally without Docker, you will need to install the required dependencies manually.

Install Dependencies
Install Python dependencies:
bash
Copy code
pip install -r requirements.txt
Install Helm (if you don't have it installed):
bash
Copy code
# For macOS
brew install helm

# For Ubuntu/Debian
curl https://raw.githubusercontent.com/helm/helm/master/scripts/get-helm-3 | bash
Run the Script
Run the main.py script to start the application:

bash
Copy code
python main.py
4. Output
The application will scan Docker images used in the Helm chart and save the results in a CSV file (e.g., 2024-11-21_vulnerability_scan_results.csv). The CSV file will include the following columns:

image:tag: The name and tag of the Docker image.
component/library: The library or component affected.
vulnerability: The vulnerability ID.
severity: The severity of the vulnerability (e.g., High, Critical, Medium).
Example Workflow
Add a Helm repository:
bash
Copy code
Enter the Helm repository name (e.g., ingress-nginx): ingress-nginx
Enter the URL for the ingress-nginx repository (e.g., https://kubernetes.github.io/ingress-nginx): https://kubernetes.github.io/ingress-nginx
Pull a specific Helm chart:
bash
Copy code
Enter the Helm chart name (e.g., ingress-nginx): ingress-nginx
Enter the version for the ingress-nginx chart (e.g., 4.11.3): 4.11.3
The application will pull the Helm chart, extract it, and render it. Then, it will scan the Docker images used in the chart for vulnerabilities.

The results will be saved in a CSV file, which can be reviewed to check for security issues.

License
This project is licensed under the MIT License - see the LICENSE file for details.

Explanation of How to Download the Docker Image and Run It:
Pull the Docker Image:

To download the Docker image from Docker Hub, run the following command:

bash
Copy code
docker pull shlomodaari1992/python-helm-scanner
Run the Docker Container:

After the image is downloaded, you can run the application using:

bash
Copy code
docker run -it shlomodaari1992/python-helm-scanner
This will start an interactive terminal session inside the Docker container where the application will prompt you for inputs and process the Helm chart and images.