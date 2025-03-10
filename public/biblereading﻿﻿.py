        import requests

        # Define the base URL and the range of file numbers
        base_url = "https://roman5.pages.dev/%E7%BD%97%E9%A9%AC%E4%B9%A65%E7%AB%A0%EF%BC%88"
        file_extension = "%EF%BC%89.mp3"

        # Loop through numbers 3 to 41
        for i in range(3, 42):  # Loop from 3 to 41 (inclusive)
            # Construct the URL for each file
            file_url = f"{base_url}{i}{file_extension}"
            
            # Send a GET request to download the file
            response = requests.get(file_url)
            
            if response.status_code == 200:
                # Save the content to a file
                with open(f"downloaded_file_{i}.mp3", "wb") as f:
                    f.write(response.content)
                print(f"File {i} downloaded successfully.")
            else:
                print(f"Failed to download file {i}.")
