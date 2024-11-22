import subprocess
import tarfile
import os
import sys
import yaml
import csv
import shutil
from datetime import datetime

def add_helm_repo(repo_name, repo_url):
    """Adds Helm to the repository and updates it."""
    try:
        print(f"Adding Helm repository: {repo_name} from {repo_url}")
        subprocess.run(["helm", "repo", "add", repo_name, repo_url], check=True)
        print("Updating Helm repositories...")
        subprocess.run(["helm", "repo", "update"], check=True)
        print(f"Helm repo '{repo_name}' added and repositories updated successfully.")
    except subprocess.CalledProcessError as e:
        print(f"Error adding or updating Helm repo: {e}")
        sys.exit(1)

def pull_helm_chart(repo_name, chart_name, chart_version):
    """Pulls Helm chart version from the repository."""
    try:
        print(f"Pulling Helm chart: {chart_name} version {chart_version}")
        subprocess.run(["helm", "pull", f"{repo_name}/{chart_name}", "--version", chart_version], check=True)
        print(f"Helm chart '{chart_name}' version '{chart_version}' pulled successfully.")
    except subprocess.CalledProcessError as e:
        print(f"Error pulling Helm chart: {e}")
        sys.exit(1)

def extract_helm_chart(file_path, file_name, extract_to="."):
    """Extract helm chart."""
    tgz_file = f"{os.path.join(file_path, file_name)}.tgz"
    try:
        if not os.path.isfile(tgz_file):
            print(f"Error: {file_name} not found at {file_path}")
            sys.exit(1)
        print(f"Extracting {file_path} to {extract_to}")
        with tarfile.open(tgz_file, "r:gz") as tar:
            tar.extractall(path=extract_to)
        print(f"Extraction complete. Files extracted to {extract_to}")
    except Exception as e:
        print(f"Error extracting {file_path}: {e}")
        sys.exit(1)

def render_helm_chart(chart_dir):
    """Render Helm chart templates to resolve any placeholders."""
    try:
        print(f"Rendering Helm chart in {chart_dir} using 'helm template'")
        result = subprocess.run(
            ["helm", "template", chart_dir],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            check=True,
        )
        rendered_output = result.stdout.decode("utf-8")
        print("Helm template rendered successfully.")
        return rendered_output
    except subprocess.CalledProcessError as e:
        print(f"Error rendering Helm chart: {e.stderr.decode()}")
        return ""

def find_images_in_rendered_output(rendered_output):
    """Parse the rendered Helm chart output to extract image names."""
    images = []
    try:
        for line in rendered_output.splitlines():
            if "image:" in line:
                parts = line.strip().split(":")
                if len(parts) > 2:
                    image_name = parts[1].strip()                    
                    image_tag = parts[2].split('@')[0].strip()
                    image_with_tag = f"{image_name}:{image_tag}"
                    # print(f" print image + tag debugging reason - image: {image_name} tag: {image_tag}")
                    if image_with_tag:
                        images.append(image_with_tag)
    except Exception as e:
        print(f"Error parsing rendered output: {e}")
    return images

def get_images_from_helm_chart(chart_dir):
    """Navigate to the helm chart dir and return a list of images from the rendered output."""
    images = []
    try:
        if os.path.exists(chart_dir):
            print(f"Processing Helm chart in directory: {chart_dir}")
        else:
            print(f"Chart directory {chart_dir} does not exist.")
            return images

        rendered_output = render_helm_chart(chart_dir)
        if rendered_output:
            images = find_images_in_rendered_output(rendered_output)

            if images:
                print("Found the following images:")
                for image in images:
                    print(f"- {image}")
            else:
                print("No images found in the rendered output.")
        else:
            print("Rendered output is empty.")
    except Exception as e:
        print(f"Error processing Helm chart: {e}")
    
    return images

def run_vulnerability_scan(images, scanner):
    """Run a vulnerability scan on each image using the specified scanner."""
    try:
        if not images:
            print("No images provided for vulnerability scan.")
            return
        
        date_str = datetime.now().strftime("%Y-%m-%d")
        output_file = f"{date_str}_vulnerability_scan_results.csv"
        
        with open(output_file, "w", newline="") as csvfile:
            fieldnames = ["image:tag", "component/library", "vulnerability", "severity"]
            writer = csv.DictWriter(csvfile, fieldnames=fieldnames)
            writer.writeheader()
        
            print(f"Running vulnerability scan using {scanner}...")
            for image in images:
                print(f"Scanning image: {image}")

                if scanner == "grype":
                    command = ["grype", image]
                elif scanner == "trivy":
                    command = ["trivy", "image", image]
                else:
                    print(f"Unsupported scanner: {scanner}")
                    return

                result = subprocess.run(command, capture_output=True, text=True)
                print(f"Scan result for {image}:")
                print(result.stdout)
                print(f"Error (if any): {result.stderr}")

                if result.returncode == 0:
                    print(f"Scan completed successfully for image: {image}")
                    vulnerabilities = []
                    if scanner == "grype":
                        vulnerabilities = process_grype_output(result.stdout, image)
                    elif scanner == "trivy":
                        vulnerabilities = process_trivy_output(result.stdout)
                    
                    if vulnerabilities:
                        print(f"Vulnerabilities found for {image}:")
                        for vuln in vulnerabilities:
                            print(vuln)
                    
                    for vuln in vulnerabilities:
                        writer.writerow(vuln)
                else:
                    print(f"Error scanning image {image}: {result.stderr}")
        
        print(f"Scan results saved to {output_file}.")
        clean_up()

    except Exception as e:
        print(f"Error running vulnerability scan: {e}")

def process_grype_output(output, image):
    """Process the output of Grype scan and return relevant vulnerabilities."""
    vulnerabilities = []
    lines = output.splitlines()
    
    for line in lines:
        # Skip lines with headers or irrelevant content
        if "NAME" in line or "Scan result" in line or "Error" in line:
            continue
        
        parts = line.split()
        # print(f"Parts for debugging: {parts}")
        if len(parts) >= 5:
            component_library = parts[0]  # The component/library 
            vulnerability = parts[4]  # The vulnerability ID
            severity = parts[-1]  # The severity level 
            
            # Only include vulnerabilities with a severity of High, Critical, or Medium
            if severity in ["High", "Critical", "Medium"]:
                vuln_data = {
                    "image:tag": image,
                    "component/library": component_library,
                    "vulnerability": vulnerability,
                    "severity": severity
                }
                vulnerabilities.append(vuln_data)
    
    return vulnerabilities




def process_trivy_output(output):
    """Process the output of trivy scan and return relevant vulnerabilities."""
    vulnerabilities = []
    lines = output.splitlines()
    
    current_image = None
    for line in lines:
        if "vulnerabilities" in line.lower():
            continue
        
        
        if line.startswith("Scanning image:"):
            current_image = line.split(":")[1].strip()  # get the image tag
            continue
        
        # Process vulnerability details (if any)
        parts = line.split("│")
        
        
        if len(parts) >= 6:
            component_library = parts[1].strip()  # The library/component 
            vulnerability = parts[2].strip()  # The vulnerability 
            severity = parts[3].strip()  # The severity
            fixed_version = parts[5].strip()  # The fixed version 

            # only include vulnerabilities with a severity of High, Critical or Medium
            if severity in ["High", "Critical", "Medium"]:
                vuln_data = {
                    "image:tag": current_image,
                    "component/library": component_library,
                    "vulnerability": vulnerability,
                    "severity": severity,
                    "fixed_version": fixed_version
                }
                vulnerabilities.append(vuln_data)
    
    return vulnerabilities



def clean_up():
    """Remove any temporary resources used to create the output."""
    temp_files = ["temp_file_1", "temp_file_2"]
    for temp_file in temp_files:
        if os.path.exists(temp_file):
            os.remove(temp_file)
            print(f"Removed temporary file: {temp_file}")
    
    if os.path.exists("chart_dir"):
        shutil.rmtree("chart_dir")
        print(f"Removed temporary directory: chart_dir")

def main():
    # User input for the helm chart information 
    repo_name =  input("Enter the Helm repository name (e.g., ingress-nginx): ").strip() 
    repo_url =  input(f"Enter the URL for the {repo_name} repository (e.g., https://kubernetes.github.io/ingress-nginx): ").strip()
    chart_name = input("Enter the Helm chart name (e.g., ingress-nginx): ").strip()
    chart_version =  input(f"Enter the version for the {chart_name} chart (e.g., 4.11.3): ").strip()
    file_path = subprocess.run(["pwd"], capture_output=True, text=True).stdout.strip()
    file_name = f"{repo_name}-{chart_version}"
    chart_dir = f"{repo_name}"

    add_helm_repo(repo_name, repo_url)
    pull_helm_chart(repo_name, chart_name, chart_version)
    extract_helm_chart(file_path, file_name)
    images_to_scan = get_images_from_helm_chart(chart_dir)

    if images_to_scan:
        run_vulnerability_scan(images_to_scan, scanner="grype")
    else:
        print("No images to scan.")

if __name__ == "__main__":
    main()
