import os
from PIL import Image, ImageDraw, ImageFont

def generate_screenshots():
    # Resolution for each image: 1200 x 675 (standard 16:9 presentation)
    width = 1200
    height = 675
    
    # Colors
    bg_color = (13, 17, 23)         # GitHub Dark background
    window_border = (48, 54, 61)     # Border
    title_bg = (22, 27, 34)         # Title bar
    term_bg = (9, 13, 19)           # Darker terminal background
    text_white = (240, 246, 252)    # White text
    text_gray = (139, 148, 158)     # Dim gray text
    text_green = (57, 211, 83)      # Green prompt
    text_cyan = (88, 166, 255)      # Cyan Info
    text_yellow = (210, 153, 34)    # Yellow Warning
    text_red = (248, 81, 73)        # Red Error
    
    # Load fonts
    font_path = "C:\\Windows\\Fonts\\consola.ttf"
    font_bold_path = "C:\\Windows\\Fonts\\consolab.ttf"
    
    if not os.path.exists(font_path):
        font_path = "arial.ttf"
        font_bold_path = "arial.ttf"
        
    font_normal = ImageFont.truetype(font_path, 22)  # Increased font size for better visibility
    font_bold = ImageFont.truetype(font_bold_path, 22)
    font_title = ImageFont.truetype(font_bold_path, 18)
    
    # Helper to draw a single centered terminal window
    def create_terminal_image(title, lines):
        img = Image.new("RGB", (width, height), bg_color)
        draw = ImageDraw.Draw(img)
        
        # Centered Window Coordinates
        x, y, w, h = 80, 50, 1040, 575
        
        # Subtle Drop shadow
        draw.rounded_rectangle([x + 10, y + 10, x + w + 10, y + h + 10], radius=14, fill=(5, 7, 10))
        
        # Window frame
        draw.rounded_rectangle([x, y, x + w, y + h], radius=14, fill=term_bg, outline=window_border, width=2)
        
        # Header bar
        draw.rounded_rectangle([x, y, x + w, y + 50], radius=14, fill=title_bg)
        # Clear bottom round corners of header
        draw.rectangle([x, y + 30, x + w, y + 50], fill=title_bg)
        # Header bottom border line
        draw.line([x, y + 50, x + w, y + 50], fill=window_border, width=2)
        
        # Mac-style Window Controls
        colors = [(255, 95, 86), (255, 189, 46), (39, 201, 63)]
        for i, color in enumerate(colors):
            cx = x + 30 + (i * 24)
            cy = y + 25
            draw.ellipse([cx - 7, cy - 7, cx + 7, cy + 7], fill=color)
            
        # Title text
        w_title_size = draw.textlength(title, font=font_title)
        draw.text((x + (w - w_title_size) // 2, y + 14), title, fill=text_gray, font=font_title)
        
        # Render text lines
        tx = x + 35
        ty = y + 75
        line_spacing = 32
        for line in lines:
            curr_x = tx
            for text, color in line:
                draw.text((curr_x, ty), text, fill=color, font=font_normal)
                curr_x += draw.textlength(text, font=font_normal)
            ty += line_spacing
            
        return img

    # Image 1: Client Terminal
    client_lines = [
        [("$ ", text_gray), ("psql -h 127.0.0.1 -p 5433 -U test-agent -d production", text_white)],
        [("Password for user test-agent: ", text_white), ("*********", text_gray)],
        [("psql (15.0, server 15.0)", text_gray)],
        [("Type \"help\" for help.", text_gray)],
        [],
        [("production=> ", text_green), ("SELECT username, email FROM users LIMIT 1;", text_white)],
        [(" username |       email       ", text_white)],
        [("----------+-------------------", text_gray)],
        [(" admin    | admin@company.com", text_white)],
        [("(1 row)", text_white)],
        [],
        [("production=> ", text_green), ("SELECT * FROM passwords;", text_white)],
        [("ERROR: AgentIAM Policy Violation: access to table passwords denied", text_red)],
        [("production=> ", text_green), ("█", text_green)]
    ]
    
    img_client = create_terminal_image("psql (test-agent@production)", client_lines)
    img_client.save("assets/client_terminal.png", "PNG")
    print("Saved: assets/client_terminal.png")

    # Image 2: Gateway Logs
    gateway_lines = [
        [("2026-07-28 09:30:00 [INFO] ", text_cyan), ("Starting AgentIAM Security Gateway...", text_white)],
        [("2026-07-28 09:30:00 [INFO] ", text_cyan), ("Using local LRU for AST Cache", text_white)],
        [("2026-07-28 09:30:00 [INFO] ", text_cyan), ("Upstream connection pool initialized size=50", text_white)],
        [("2026-07-28 09:30:00 [INFO] ", text_cyan), ("Registered File Audit Sink path=./audit.log", text_white)],
        [("2026-07-28 09:30:00 [INFO] ", text_cyan), ("AgentIAM Proxy Listening addr=127.0.0.1:5433", text_white)],
        [("2026-07-28 09:30:05 [INFO] ", text_cyan), ("Connection accepted remote_addr=127.0.0.1:51240", text_white)],
        [("2026-07-28 09:30:05 [INFO] ", text_cyan), ("Protocol detected protocol=postgres", text_white)],
        [("2026-07-28 09:30:05 [INFO] ", text_cyan), ("Authentication successful client_id=test-agent", text_white)],
        [("2026-07-28 09:30:10 [INFO] ", text_cyan), ("Intercepted Query client_id=test-agent", text_white)],
        [("    query=\"SELECT username, email FROM users LIMIT 1\"", text_gray), (" status=success", text_green)],
        [("2026-07-28 09:30:15 [WARN] ", text_yellow), ("Intercepted Query client_id=test-agent", text_white)],
        [("    query=\"SELECT * FROM passwords\"", text_gray), (" status=blocked", text_red)],
        [("    error=\"access to table passwords denied\"", text_red)],
        [("█", text_white)]
    ]
    
    img_gateway = create_terminal_image("agentiam-gateway-daemon", gateway_lines)
    img_gateway.save("assets/gateway_logs.png", "PNG")
    print("Saved: assets/gateway_logs.png")

    # Image 3: policies.yaml
    yaml_key = (121, 192, 255)       # Light blue for keys
    yaml_val = (255, 123, 114)       # Coral/orange for values
    yaml_comm = (139, 148, 158)      # Gray for comments
    
    yaml_lines = [
        [("# yaml-language-server: $schema=./policies.schema.json", yaml_comm)],
        [("agents:", yaml_key)],
        [("  - name: ", yaml_key), ("test-agent", yaml_val)],
        [("    key: ", yaml_key), ("\"$2a$10$OAiS23oL4WZ0Db...\"", yaml_val), ("  # bcrypt password hash", yaml_comm)],
        [("    allowed_statements: ", yaml_key), ("[\"SELECT\", \"INSERT\", \"SET\"]", yaml_val)],
        [("    allowed_tables: ", yaml_key), ("[\"users\", \"orders\"]", yaml_val)],
        [("    blocked_functions: ", yaml_key), ("[\"sleep\"]", yaml_val)],
        [("    select_limit: ", yaml_key), ("20000", yaml_val)],
        [("    max_complexity: ", yaml_key), ("50", yaml_val), ("        # AST joins/aggregates scorer", yaml_comm)],
        [("    rate_limit_rpm: ", yaml_key), ("60", yaml_val)],
        [("    pool_mode: ", yaml_key), ("transaction", yaml_val), ("     # stateful connection pooling", yaml_comm)],
        [("    dialect: ", yaml_key), ("postgres", yaml_val)]
    ]
    
    img_yaml = create_terminal_image("policies.yaml", yaml_lines)
    img_yaml.save("assets/policies_yaml.png", "PNG")
    print("Saved: assets/policies_yaml.png")

if __name__ == "__main__":
    generate_screenshots()
