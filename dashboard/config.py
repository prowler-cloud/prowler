import os

# Emojis to be used in the compliance table
pass_emoji = "✅"
fail_emoji = "❌"
info_emoji = "ℹ️"
manual_emoji = "✋🏽"

# Main colors
fail_color = "#e67272"
pass_color = "#54d283"
info_color = "#2684FF"
manual_color = "#636c78"

# Muted colors
muted_fail_color = "#fca903"
muted_pass_color = "#03fccf"
muted_manual_color = "#b33696"

# Severity colors
critical_color = "#951649"
high_color = "#e11d48"
medium_color = "#ee6f15"
low_color = "#fcf45d"
informational_color = "#3274d9"

# Folder output path
folder_path_overview = os.getcwd() + "/output"
folder_path_compliance = os.getcwd() + "/output/compliance"

encoding_format = "utf-8"
# Error action, it is recommended to use "ignore" or "replace"
error_action = "ignore"
