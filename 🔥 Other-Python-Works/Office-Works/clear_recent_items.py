import os
import shutil

# ANSI escape codes for colors and styles
class Style:
    GREEN = '\033[92m'  # Green
    RED = '\033[91m'    # Red
    BLUE = '\033[94m'   # Blue
    BOLD = '\033[1m'    # Bold
    END = '\033[0m'     # Reset

def delete_recent_items():
    # Path to the Recent Items directory
    recent_path = os.path.join(os.getenv('APPDATA'), r'Microsoft\Windows\Recent')

    # Check if the Recent folder exists
    if not os.path.exists(recent_path):
        print(Style.RED + "Recent Items folder does not exist. Creating it..." + Style.END)
        try:
            os.makedirs(recent_path)
            print(Style.GREEN + "Recent Items folder created." + Style.END)
        except PermissionError:
            print(Style.RED + "Access denied: Cannot create Recent folder. Run as Administrator." + Style.END)
            return

    try:
        contents = os.listdir(recent_path)
    except PermissionError:
        print(Style.RED + "Access denied: Cannot open Recent folder. Run the script as Administrator." + Style.END)
        return

    # If empty
    if not contents:
        print(Style.GREEN + "Recent Items directory is already empty." + Style.END)
        return

    # Ask user
    user_input = input(Style.BOLD + "Are you sure you want to delete all recent items? (yes/no): " + Style.END).lower()

    if user_input == "yes":
        for item in contents:
            item_path = os.path.join(recent_path, item)
            try:
                if os.path.isfile(item_path) or os.path.islink(item_path):
                    os.remove(item_path)
                elif os.path.isdir(item_path):
                    shutil.rmtree(item_path)
            except PermissionError:
                print(Style.RED + f"Access denied: Could not delete {item}" + Style.END)
            except Exception as e:
                print(Style.RED + f"Error deleting {item}: {str(e)}" + Style.END)
        print(Style.GREEN + "All accessible recent items have been deleted." + Style.END)
    elif user_input == "no":
        print(Style.BLUE + "Operation cancelled." + Style.END)
    else:
        print(Style.RED + "Invalid input. Operation cancelled." + Style.END)

if __name__ == "__main__":
    delete_recent_items()
