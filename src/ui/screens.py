import curses
import time
import re
import os
import logging
from ui.input import TextInput, RichLine

class BaseScreen:
    """Interface for all screens"""
    def __init__(self, stdscr, engine):
        self.stdscr = stdscr
        self.engine = engine
        self.height, self.width = stdscr.getmaxyx()

    def resize(self):
        self.height, self.width = self.stdscr.getmaxyx()

    def draw(self):
        """Main render loop for this screen"""
        pass

    def handle_input(self, key):
        """
        Main input handler.
        Returns: None (usually), or a new Screen instance to switch context.
        """
        pass

class LockScreen(BaseScreen):
    
    def __init__(self, stdscr, engine):
        super().__init__(stdscr, engine)
        self.NEW_ACCOUNT_STR = "CREATE NEW"
        curses.curs_set(0)
        # inputs
        self.name_box = TextInput(prompt="Account Name: ", password=False)
        self.passwd_box = TextInput(prompt="Password: ", password=True)
        
        # initial state
        accounts = self.engine.vault_names()
        self.is_setup = len(accounts) == 0
        default_acc = False
        if self.engine.acc_name:
            default_acc = self.engine.acc_name
        if not default_acc and self.engine.sys_config.get("default_acc"):
            if engine.vault_exists(self.engine.sys_config.get("default_acc")):
                default_acc = self.engine.sys_config.get("default_acc")
        
        # initial focus
        self.focus_box = self.name_box
        self.show_acc_switcher = (not self.is_setup and not default_acc)
        self.switcher_idx = 0
        
        if self.is_setup:
            self.msg = "CREATE NEW VAULT"
        else:
            self.msg = "LOCKED"
            if default_acc:
                # Pre-fill name and jump to password
                self.engine.set_account(default_acc)
                self.name_box.buffer = list(default_acc)
                self.focus_box = self.passwd_box

    def handle_input(self, key):
        if key == 9:
            #TAB
            if not self.is_setup:
                self.show_acc_switcher = True
            else:
                # Setup mode
                self.focus_box = self.passwd_box if self.focus_box == self.name_box else self.name_box
            return
        elif key == 27:
            #ESC
            return "QUIT"

        if self.show_acc_switcher:
            #account switcher
            names = self.engine.vault_names() + [self.NEW_ACCOUNT_STR]
            if key == curses.KEY_UP:
                self.switcher_idx = (self.switcher_idx - 1) % len(names)
            elif key == curses.KEY_DOWN:
                self.switcher_idx = (self.switcher_idx + 1) % len(names)
            elif key in (10, 13, curses.KEY_ENTER):
                selection = names[self.switcher_idx]
                if selection == self.NEW_ACCOUNT_STR:
                    self.is_setup = True
                    self.focus_box = self.name_box
                    self.msg = "CREATE VAULT"
                    self.name_box.reset()
                else:
                    self.engine.set_account(selection)
                    self.name_box.buffer = list(selection)
                    self.is_setup = False
                    self.focus_box = self.passwd_box
                    self.msg = "LOCKED"
                self.show_acc_switcher = False
            self.passwd_box.reset()
            return

        result = self.focus_box.handle_key(key)
        if isinstance(result, str): # Enter was pressed in the focused box
            acc_name = self.name_box.get_text()
            password = self.passwd_box.get_text()
            #Check unique name and allowed chars
            if self.check_name(acc_name):
                if self.is_setup:
                    if self.engine.vault_exists(acc_name) or acc_name == "GLOBAL":
                        self.msg = f"'{acc_name}' ALREADY TAKEN/RESERVED"
                        self.focus_box = self.name_box
                        return
                    #Create account
                    self.msg = f"CREATING {acc_name}..."
                    self.engine.acc_name = acc_name
                    self.engine.create_account(password)
                    self.is_setup = False
                    self.show_acc_switcher = True
                else:
                    #Attempt login
                    self.msg = "DECRYPTING..."
                    if self.engine.login(acc_name, password):
                        return ChatScreen(self.stdscr, self.engine)
                    else:
                        self.msg = "DECRYPTION ERROR"
                        self.passwd_box.reset()
            else:
                self.name_box.reset()
                self.passwd_box.reset()
                return

    def check_name(self, name: str):
        if not name.strip():
            self.msg = "ACCOUNT NAME REQUIRED"
            self.focus_box = self.name_box
            return 0
        if name == "GLOBAL":
            self.msg = "NAME 'GLOBAL' RESERVED"
            self.focus_box = self.name_box
            return 0
        if re.search(r'[^a-zA-Z0-9_-]', name):
            self.msg = "NAME CANNOT HAVE SPACES OR SPECIAL CHARS"
            self.focus_box = self.name_box
            return 0
        return 1
    def draw(self):
        self.stdscr.clear()
        cy, cx = self.height // 2, self.width // 2
        
        # title
        title = "VAULT SETUP" if self.is_setup else "FR3Q VAULT"
        self.stdscr.addstr(cy - 6, cx - len(title)//2, title, curses.A_BOLD)

        self.stdscr.addstr(cy - 2, cx - len(self.msg)//2, self.msg, curses.color_pair(2) | curses.A_DIM)
        vpath = self.engine._get_vault_path(self.name_box.get_text() or "*")
        if self.show_acc_switcher:
            #draw acc switcher
            self.draw_acc_switcher()
            self.stdscr.addstr(self.height-1, 0, "ESC: Quit", curses.color_pair(25))
        else:
            if self.is_setup:
                # name box
                self.name_box.draw(self.stdscr, cy, cx - 15, 30, 8)
                if self.focus_box == self.name_box:
                    # Highlight prompt
                    self.stdscr.addstr(cy, cx - 15, self.name_box.prompt, curses.color_pair(16) | curses.A_BOLD)
                self.stdscr.addstr(self.height-1, 0, "TAB: Switch Field | ESC: Quit", curses.color_pair(25))
            else:
                self.stdscr.addstr(self.height-1, 0, "TAB: Switch Account | ESC: Quit", curses.color_pair(25))
            self.stdscr.addstr(cy - 4, cx - 18, vpath[-36:], curses.color_pair(13))
            # password box
            pass_y = cy + 2 if self.is_setup else cy
            self.passwd_box.draw(self.stdscr, pass_y, cx - 11, 30, 8, 8)
            if self.focus_box == self.passwd_box:
                # Highlight prompt
                self.stdscr.addstr(pass_y, cx - 11, self.passwd_box.prompt, curses.color_pair(16) | curses.A_BOLD)
        
            
    def draw_acc_switcher(self):
        names = self.engine.vault_names() + [self.NEW_ACCOUNT_STR]
        h, w = len(names) + 5, 30
        sy, sx = (self.height - h) // 2, (self.width - w) // 2
        cy, cx = self.height // 2, self.width // 2

        for i in range(h):
            self.stdscr.addstr(sy+i, sx, " " * w, curses.color_pair(0))
        
        self.stdscr.addstr(cy - 2, cx - 7, "SELECT ACCOUNT", curses.A_BOLD | curses.color_pair(16)) 
        
        for i, name in enumerate(names):
            is_sel = (i == self.switcher_idx)
            prefix = "  "
            if is_sel:
                if name != self.NEW_ACCOUNT_STR:
                    vpath = self.engine._get_vault_path(name)
                    prefix = "> "
                else:
                    vpath = self.engine._get_vault_path("*")
                    prefix = "+ "
                color = curses.color_pair(8) | curses.A_REVERSE
            else:
                color = curses.color_pair(25)
            self.stdscr.addstr(cy+i, sx+6, f"{prefix}{name}", color)
        self.stdscr.addstr(cy - 4, cx - 18, vpath[-36:], curses.color_pair(13))

class ChatScreen(BaseScreen):
    """
    The Main Interface: Chat Log, Status Bar, Command Input.
    """
    def __init__(self, stdscr, engine):
        super().__init__(stdscr, engine)
        self.logs = [] # RichLines
        self.buffer = [] # visual lines
        self.chat_scrl_off = 0
        self.menu_scrl_off = 0
        self.input_box = TextInput(prompt=">> ", draw_cursor=True)
        self.show_overlay = False
        self.active_overlay = None
        self.overlay_args = {}
        self.print_banner()
        self._reflow_buffer()

    def resize(self):
        super().resize()
        self._reflow_buffer()
        # Clamp scroll offset
        max_scroll = max(0, len(self.buffer) - (self.height - 2))
        if self.chat_scrl_off > max_scroll:
            self.chat_scrl_off = max_scroll

    
    # Chat log commands
    def refresh_view(self, history: list):
        """
        Hard reset of the local log buffer using a provided list of 
        formatted history dictionaries from the Engine.
        """
        self.logs = []
        self.buffer = []
        self.chat_scrl_off = 0
        for msg in history:
            self.push_chat_message(
                sender_nick=msg['nick'],
                text=msg['text'],
                timestamp=msg['time'],
                sender_color=msg['sender_color'],
                text_color=msg['text_color'],
                colon=msg['colon']
            )

    def push_chat_message(self, sender_nick, text, timestamp, sender_color=16, text_color=0, colon=True):
        """
        Formats and adds a persistent chat message to the buffer.
        """
        line = RichLine(is_chat=True)
        line.add(16, "[")
        line.add(25, f"{timestamp}")
        line.add(16, "][")
        line.add(sender_color, f"{sender_nick}")
        line.add(16, "]")
        if colon:
            line.add(16, ":")
        else:
            line.add(16, " ")
        line.add(text_color, text)
        self.logs.append(line)
        
        width = self.width - 1
        wrapped = self._wrap_rich_line(line, width)
        idx = len(self.logs) - 1
        for segs in wrapped:
            self.buffer.append({'index': idx, 'segments': segs})

    def push_system_log(self, text, color_id=25):
        """
        Adds a non-persistent system notification or ASCII art to the buffer.
        Marked with is_chat=False so it can be cleared.
        """
        line = RichLine(is_chat=False)
        line.add(color_id, text)
        self.logs.append(line)
        
        width = self.width - 1
        wrapped = self._wrap_rich_line(line, width)
        idx = len(self.logs) - 1
        for segs in wrapped:
            self.buffer.append({'index': idx, 'segments': segs})

    def clear_non_chat(self):
        """
        Clears all non chat from active chat log
        """
        # Filter the list based on the is_chat flag in rich line
        self.logs = [line for line in self.logs if line.is_chat]
        self._reflow_buffer()
        self.chat_scrl_off = 0

    def clear_logs(self):
        self.logs = []
        self.buffer = []
        self.chat_scrl_off = 0

    def _reflow_buffer(self):
        self.buffer = []
        width = self.width - 1
        for i, log in enumerate(self.logs):
            lines = self._wrap_rich_line(log, width)
            for segs in lines:
                self.buffer.append({'index': i, 'segments': segs})

    def _wrap_rich_line(self, log, width):
        lines = []
        if not log.segments:
            return lines
        
        prefix_segments = log.segments[:-1]
        message_segment = log.segments[-1]
        
        prefix_len = sum(len(text) for _, text in prefix_segments)
        
        current_row = list(prefix_segments)
        current_x = prefix_len
        
        color_id, message_text = message_segment
        
        for char in message_text:
            if current_x >= width:
                lines.append(current_row)
                current_row = [(color_id, char)]
                current_x = 1
            else:
                if current_row and current_row[-1][0] == color_id:
                    c, t = current_row.pop()
                    current_row.append((c, t + char))
                else:
                    current_row.append((color_id, char))
                current_x += 1
        
        if current_row:
            lines.append(current_row)
        return lines

    # Drawing
    def draw(self):
        self.stdscr.clear()
        info = self.engine.get_status_bar_info()
        self.draw_status_bar(info)

        chat_width = self.width - 1
        chat_height = self.height - 2
        target = info['server'] if info['room'] == "GLOBAL" else info['room']
        unread_count = info['notifications'].get(target, 0)
        
        separator_log_idx = -1
        if unread_count > 0:
            # Scan backwards from the end of self.logs to find the index of the Nth "real" message.
            # This correctly places the separator above chat messages, skipping over any join/left messages.
            logs_to_scan = reversed(list(enumerate(self.logs)))
            real_messages_found = 0
            for idx, log in logs_to_scan:
                # A real message has a ':' segment (chat) or uses color 7 (file). 
                # A join/left message has neither.
                is_real_message = any(seg[1] == ":" or seg[0] == 7 for seg in log.segments)
                if is_real_message:
                    real_messages_found += 1
                
                if real_messages_found >= unread_count:
                    separator_log_idx = idx
                    break
        
        view_lines = []
        current_buf_idx = len(self.buffer) - 1 - self.chat_scrl_off
        lines_collected = 0
        
        while current_buf_idx >= 0 and lines_collected < chat_height:
            line_data = self.buffer[current_buf_idx]
            idx = line_data['index']
            segs = line_data['segments']
            
            view_lines.append(("MSG", segs))
            lines_collected += 1
            
            if lines_collected >= chat_height:
                break
            
            # Check for separator (inserted above the current line if it's the first line of the target message)
            if unread_count > 0 and idx == separator_log_idx:
                is_first_line = False
                if current_buf_idx == 0:
                    is_first_line = True
                elif self.buffer[current_buf_idx - 1]['index'] != idx:
                    is_first_line = True
                
                if is_first_line:
                    view_lines.append(("SEPARATOR", unread_count))
                    lines_collected += 1
            
            current_buf_idx -= 1
            
        view_lines.reverse()

        # Draw logs
        y_cursor = 1
        for row_type, content in view_lines:
            if y_cursor >= self.height - 1: break
            if row_type == "SEPARATOR":
                self.draw_unread_separator(y_cursor, unread_count)
            else:
                self.draw_wrapped_line(y_cursor, content)
            y_cursor += 1
        # Draw Transfer Progress (if any)
        if info.get("transfers"):
            self.draw_transfers(info["transfers"])
        # TAB OVERLAY (Draw on top if active)
        if self.show_overlay:
            if self.active_overlay in (None, "lists"):
                self.draw_lists(info)
            elif self.active_overlay == "whois":
                key = self.overlay_args.get("key")
                alias = self.overlay_args.get("alias", None)
                self.draw_whois(key, alias)
            elif self.active_overlay == "who":
                self.draw_who()
            
        # draw chat arrow
        if self.chat_scrl_off > 0:
            self.stdscr.addstr(self.height - 2, (self.width//2) - 3, "  vvv  ", curses.color_pair(5))
        # Draw PS1
        if info['server'] == "NONE":
            conn_col = 8
        else:
            conn_col = 15
        text = self.input_box.get_text()
        bash_col = self.bash_to_col(text)
        self.input_box.prompt = f"{info['nick']}@freq # "
        self.input_box.draw(self.stdscr, self.height - 1, 0, self.width, ps1_colors=[13,conn_col,4,bash_col])

    def bash_to_col(self, text):
        #command dictionary
        valid_cmds = [
            "/friend","/join","/leave","/nick","/del","/file","/ft","/connect",
            "/c","/disconnect","/clean","/server","/s","/n","/exit","/policy","/dc",
            "/refresh","/r","/default","/proxy", "/quit", "/q", "/whois", "/who"
        ]
        if text.startswith("/file ") or text.startswith("/ft "):
            return 5
        if not text.startswith("/"):
            return 13
        parts = text.split(" ", 1)
        cmd = parts[0]
        if cmd in valid_cmds:
            return 12
        return 10

    def draw_transfers(self, transfers):
        # top right, below status bar
        row = 1
        for _, t in transfers.items():
            if row > 3: break # Max 3 bars
            pct = int((t['current'] / t['total']) * 100) if t['total'] > 0 else 0
            
            c_main = 21 if t['type'] == "TX" else 20 # 13=Cyan(TX), 12=Green(RX)
            name = t['name']
            if len(name) > 10: name = name[:8] + ".."
            
            bar_len = 20
            filled = int((pct / 100) * bar_len)
            
            segments = []
            segments.append((c_main, f" {t['type']} "))
            segments.append((16, f"{name} "))
            segments.append((8, "["))
            segments.append((c_main, " " * filled))
            segments.append((25, " " * (bar_len - filled)))
            segments.append((8, "] "))
            segments.append((16, f"{pct}% "))

            total_len = sum(len(s[1]) for s in segments)
            start_x = self.width - total_len - 1
            if start_x > 0:
                self.draw_wrapped_line(row, segments, xOffset=start_x)
            row += 1

    def draw_status_bar(self, info):
        try:
            ver_text = f" FR3Q (v{info['ver']}) "
            room_text = f" {info['room']}"
            server_text = f"{info['server']} "
            num_peers = len(info['peers']) - 1 if info['peers'] else 0
            peers_text = f"({num_peers})"
            status_box = f"  {info['status']}   "
            noti_str = None

            #Count notifications
            total_notis = 0
            for room in info['notifications']:
                number = info['notifications'].get(room, 0)
                total_notis += number
            if total_notis > 0:
                noti_str = f" *{str(total_notis)}"
            
            # resolve color
            if info['tor']:
                status_color = curses.color_pair(23) if info['server'] != "NONE" else curses.color_pair(7) | curses.A_REVERSE
            else:
                status_color = curses.color_pair(25) | curses.A_REVERSE
                
            base_color = curses.color_pair(25) | curses.A_REVERSE
            active_status_color = status_color | curses.A_BOLD

            center_x = self.width // 2
            
            # bg
            self.stdscr.addstr(0, 0, " " * self.width, base_color)

            self.stdscr.addstr(0, 0, ver_text, base_color)

            # place
            self.stdscr.addstr(0, center_x, "@", base_color)
            self.stdscr.addstr(0, center_x - len(room_text), room_text, base_color)
            self.stdscr.addstr(0, center_x + 1, server_text, base_color)

            # peers
            self.stdscr.addstr(0, center_x + 1 + len(server_text), peers_text, base_color)

            # notis
            if noti_str:
                self.stdscr.addstr(0, center_x + 1 + len(server_text) + len(peers_text), noti_str, curses.color_pair(28))
            # status bar
            start_x_status = self.width - len(status_box)
            if start_x_status > 0:
                self.stdscr.addstr(0, start_x_status-1, "|", base_color)
                self.stdscr.addstr(0, start_x_status, status_box, active_status_color)
                self.stdscr.addstr(0, self.width-1, "|", base_color)

        except curses.error:
            pass

    def draw_unread_separator(self, y, count):
        """ draws --- Unread (count) ------"""
        label = f" ---------- Unread ({count}) "
        bar = label.ljust(self.width - 1, "-")
        try:
            self.stdscr.addstr(y, 0, bar, curses.color_pair(5))
        except curses.error: pass

    def draw_wrapped_line(self, y, segments, xOffset=0):
        current_x = xOffset
        for color_id, text in segments:
            try:
                self.stdscr.addstr(y, current_x, text, curses.color_pair(color_id))
                current_x += len(text)
            except curses.error: pass

    def draw_info_box(self):
        # Dimensions
        h, w = self.height - 4, self.width - 8
        sy, sx = 2, 4
        max_view_rows = h - 4 
        
        try:
            # Box
            for i in range(h):
                # Background frame
                self.stdscr.addstr(sy+i, sx, " " * w, curses.color_pair(8) | curses.A_REVERSE)
                if i not in (0, h - 1):
                    # content area
                    self.stdscr.addstr(sy+i, sx+1, " " * (w - 2), curses.color_pair(27))
        except curses.error:
            pass
        except Exception as e:
            logging.debug(f"draw_info_box crashed:{e}")
            pass

    def draw_lists(self, info):
        """Helper to draw the Server/Alias list popup with scrolling"""
        # Dimensions
        h, w = self.height - 4, self.width - 8
        sy, sx = 2, 4
        max_view_rows = h - 4 
        self.draw_info_box()

        try:
            servers_dict = self.engine.profile_cache.get('servers', {})
            aliases_dict = self.engine.profile_cache.get('aliases', {})
            links = self.engine.profile_cache.get('server_links', {})
            total_items = max(len(servers_dict), len(aliases_dict))
            can_go_up = self.menu_scrl_off > 0
            can_go_down = total_items > (self.menu_scrl_off + max_view_rows)

            # Current status info
            current_server = info['server']
            current_room = info['room']
            notifications = info['notifications']
            server_link_list = links.get(current_server, []) # List of aliases linked to active server

            # Slicing the lists based on scroll offset
            server_items = list(servers_dict.items())[self.menu_scrl_off : self.menu_scrl_off + max_view_rows]
            alias_items = list(aliases_dict.keys())[self.menu_scrl_off : self.menu_scrl_off + max_view_rows]

            # Headers
            self.stdscr.addstr(sy+1, sx+2, " SERVERS ", curses.A_BOLD)
            mid_x = sx + w//2
            self.stdscr.addstr(sy+1, mid_x+2, " ALIASES ", curses.A_BOLD)

            # Servers
            for i, (name, url) in enumerate(server_items):
                is_active = (name == current_server)
                if is_active:
                    color = curses.color_pair(15)
                    prefix = "@ "
                else:
                    color = curses.color_pair(8)
                    prefix = "  "
                
                txt = f"{prefix}{name}"
                # Truncate to avoid overlapping columns
                self.stdscr.addstr(sy+3+i, sx+2, txt[:(w//2)-4], color)
                if name in notifications:
                    if notifications[name] > 0:
                        #print notification indicator
                        self.stdscr.addstr(sy+3+i, sx+3+len(txt[:(w//2)-4]), f"*{str(notifications[name])}", curses.color_pair(10))

            # Aliases
            in_dm = current_room != "GLOBAL"
            for i, name in enumerate(alias_items):
                is_dm = (name == current_room)
                is_linked = aliases_dict[name] in server_link_list
                online = aliases_dict[name] in self.engine.peers
                key = aliases_dict[name]
                color = curses.color_pair(self.engine.ident_color(key))
                if is_linked:
                    prefix = " - "
                    color = curses.color_pair(12)
                    if in_dm and not is_dm:
                        #linked but not target
                        color = curses.color_pair(4) if online else curses.color_pair(25)
                else:
                    color = curses.color_pair(25)
                    prefix = "   "
                pcolor = 12 if online else 8
                self.stdscr.addstr(sy+3+i, mid_x+2, prefix, curses.color_pair(pcolor))
                self.stdscr.addstr(sy+3+i, mid_x+5, name[:(w//2)-8], color)
                if name in notifications:
                    if notifications[name] > 0:
                        #print notification indicator
                        self.stdscr.addstr(sy+3+i, mid_x+6+len(name[:(w//2)-8]), f"*{str(notifications[name])}", curses.color_pair(10))

            # Scroll indicator
            if can_go_up:
                self.stdscr.addstr(sy, mid_x - 2, " ^^^ ", curses.color_pair(8) | curses.A_REVERSE)
            if can_go_down:
                self.stdscr.addstr(sy + h - 1, mid_x - 2, " vvv ", curses.color_pair(8) | curses.A_REVERSE)

        except curses.error:
            pass
        except Exception as e:
            logging.debug(f"draw_lists crashed:{e}")
            pass

    def draw_whois(self, key: str, alias: str=None):
        # Dimensions
        h, w = self.height - 4, self.width - 8
        sy, sx = 2, 4
        max_view_rows = h - 4
        self.draw_info_box()
        aliases_dict = self.engine.profile_cache.get('aliases', {})
        links = self.engine.profile_cache.get('server_links', {})
        if alias:
            #is alias
            target = alias
        else:
            #not alias
            target = key
        try:
            mid_x = sx + w//2
            msg_policy = "ALLOW" if self.engine.rule_query(0x01, key) else "DENY"
            file_policy = "ALLOW" if self.engine.rule_query(0x02, key) else "DENY"
            session_status = "True" if self.engine.vault.has_session(bytes.fromhex(key)) else "False"
            key_color = self.engine.ident_color(key)
            status = ""
            if key_color == 15:
                status = "ONLINE, BLOCKED"
            elif key_color == 9:
                status = "OFFLINE, BLOCKED"
            elif key_color in (12, 11):
                status = "ONLINE"
            elif key_color in (25, 2):
                status = "OFFLINE"
            elif key_color == 13:
                status = "YOU"
            #title
            self.stdscr.addstr(sy+2, mid_x-(len(target)//2), target, curses.color_pair(key_color) | curses.A_BOLD)
            sy += 1
            self.stdscr.addstr(sy+3, mid_x-(len(status)//2), status, curses.color_pair(25))
            sy += 1
            #info
            self.stdscr.addstr(sy+4, sx+2, "  KEY: ", curses.color_pair(25))
            self.stdscr.addstr(sy+4, sx+9, key, curses.color_pair(key_color))
            self.stdscr.addstr(sy+5, sx+2, "  MSG: ", curses.color_pair(25))
            self.stdscr.addstr(sy+5, sx+9, msg_policy, curses.color_pair(12 if msg_policy == "ALLOW" else 9))
            self.stdscr.addstr(sy+6, sx+2, " FILE: ", curses.color_pair(25))
            self.stdscr.addstr(sy+6, sx+9, file_policy, curses.color_pair(12 if file_policy == "ALLOW" else 9))
            self.stdscr.addstr(sy+7, sx+2, " SESH: ", curses.color_pair(25))
            self.stdscr.addstr(sy+7, sx+9, session_status, curses.color_pair(8))

            self.stdscr.addstr(sy+9, sx+2, " SEEN: ", curses.color_pair(25))
            i = 0
            for server in links:
                llist = links[server]
                if key in llist and sy+10+i < h:
                    self.stdscr.addstr(sy+10+i, sx+9, server, curses.color_pair(8))
                    i += 1

        except curses.error:
            pass
        except Exception as e:
            logging.debug(f"draw_whois crashed:{e}")
            pass

    def draw_who(self):
        # Dimensions
        h, w = self.height - 4, self.width - 8
        sy, sx = 2, 4
        max_view_rows = h - 4
        self.draw_info_box()
        peers = self.engine.peers
        aliases = self.engine.profile_cache.get('aliases', {})
        server = self.engine.current_server_name
        try:
            mid_x = sx + w//2
            if server:
                self.stdscr.addstr(sy+2, mid_x-(len(server)//2), server, curses.A_BOLD)
            else:
                self.stdscr.addstr(sy+2, mid_x-3, " NONE ", curses.A_BOLD)
            if peers:
                i = 0
                for peer in peers:
                    ident_color = self.engine.ident_color(peer)
                    for name in aliases:
                        key = aliases[name]
                        if key == peer:
                            peer += f" ({name})"
                    if sy+4+i < h:
                        self.stdscr.addstr(sy+4+i, sx+2, "- " + peer, curses.color_pair(ident_color))
                    i += 1
            else:
                self.stdscr.addstr(sy+4, mid_x-3, " NONE ", curses.color_pair(25))
        except curses.error:
            pass
        except Exception as e:
            logging.debug(f"draw_who crashed:{e}")
            pass



    def print_banner(self):
        chunks = [
            r"  ______   ______    ","        ",r"   ______        ",
            r" /_____/\ /_____/\  ","  ______ ",r"  /_____/\       ",
            r" \::::_\/_\:::_ \ \  ","/_____/\\ ",r" \:::_ \ \      ",
            r"  \:\/___/\\:(_) ) )_","\:::_:\ \\ ",r" \:\ \ \ \_    ",
            r"   \:::._\/ \: __ `\ \ "," /_\:\ \\ ",r" \:\ \ /_ \   ",
            "    \:\ \    \ \ `\ \ \\"," \::_:\ \\ ",r" \:\_-  \ \  ",
            r"     \_\/     \_\/ \_\/",r" /___\:\ ' ",r" \___|\_\_/ ",
            r"                        ",r"\______/",r"             "
        ]
        
        for i in range(8):
            row_line = RichLine()
            for j in range(3):
                text_segment = chunks[(i * 3) + j]
                color = 12 if j == 1 else 0
                row_line.add(color, text_segment)
            self.logs.append(row_line)
    # Input
    def handle_input(self, key):
        # Check for Overlays/Screens
        if key == 9: # Tab
            self.show_overlay = not self.show_overlay
            self.active_overlay = None
            return
        if key == 27: # ESC
            return ConfigScreen(self.stdscr, self.engine)
        #Scrolling
        if key == curses.KEY_UP:
            if self.show_overlay:
                #overlay scroll
                if self.menu_scrl_off > 0:
                    self.menu_scrl_off -= 1
            else:
            #chat scroll
                max_scroll = max(0, len(self.buffer) - (self.height - 2))
                if self.chat_scrl_off < max_scroll:
                    self.chat_scrl_off += 1
        elif key == curses.KEY_DOWN:
            if self.show_overlay:
                #overlay type
                if self.active_overlay in (None, "lists"):
                    num_servers = len(self.engine.profile_cache.get('servers', {}))
                    num_aliases = len(self.engine.profile_cache.get('aliases', {}))
                    max_items = max(num_servers, num_aliases)
                    #overlay scroll
                    if self.menu_scrl_off < max_items - (self.height - 8):
                        self.menu_scrl_off += 1
            else:
                #chat scroll
                if self.chat_scrl_off > 0:
                    self.chat_scrl_off -= 1

        result = self.input_box.handle_key(key)
        if isinstance(result, str):
            # The user pressed Enter! result is the command string.
            if result:
                self.engine.handle_input(result)
                self.chat_scrl_off = 0
                self.input_box.reset()
        
class ConfigScreen(BaseScreen):
    """
    Dashboard view for Profile fields and System Info.
    """
    def draw(self):
        curses.curs_set(0)
        self.stdscr.clear()
        
        header = f" CLIENT "
        self.stdscr.addstr(0, 0, f"{header:<{self.width}}", curses.A_REVERSE | curses.A_BOLD)

        # Fetch Data
        my_id = self.engine.vault.get_my_identity_hex() if self.engine.vault else "LOCKED"
        profile = self.engine.profile_cache
        info = self.engine.get_status_bar_info()
        # Parse Data
        #version
        ver = getattr(self.engine, 'ptver', '!!!')
        #connection
        if info['tor']:
            if info['server'] != "NONE":
                #Connected
                proxy_status_color = curses.color_pair(15)
                proxy_status = "Connected"
            else: 
                #Avaliable
                proxy_status_color =curses.color_pair(7)
                proxy_status = "Avaliable"
        else:
            #Disconnected/Unavaliable
            proxy_status_color = curses.color_pair(8)
            proxy_status = "Unavaliable"
        if len(info['peers']) > 0:
            peer_count = len(info['peers']) - 1
        else:
            peer_count = 0
        #policies
        mpolicy = profile.get("msg_policy", {})
        fpolicy = profile.get("file_policy", {})
        mgpolicy = mpolicy.get("mode", "deny")
        fgpolicy = fpolicy.get("mode", "deny")
        limit = profile.get("max_msg_size", 1000000)
        str_file_policy = fgpolicy.upper()
        str_msg_policy = mgpolicy.upper()

        if fgpolicy == "allow":
            file_policy_color = curses.color_pair(12)
            exceptions = len(fpolicy.get("blacklist", []))
            if exceptions > 0:
                str_file_policy += f" (!{exceptions})"
        elif fgpolicy == "whitelist":
            file_policy_color = curses.color_pair(16)
            exceptions = len(fpolicy.get("whitelist", []))
            if exceptions > 0:
                str_file_policy += f" ({exceptions})"
        else:
            file_policy_color = curses.color_pair(9)
        if mgpolicy == "allow":
            msg_policy_color = curses.color_pair(12)
            exceptions = len(mpolicy.get("blacklist", []))
            if exceptions > 0:
                str_msg_policy += f" (!{exceptions})"
        elif mgpolicy == "whitelist":
            msg_policy_color = curses.color_pair(16)
            exceptions = len(mpolicy.get("whitelist", []))
            if exceptions > 0:
                str_msg_policy += f" ({exceptions})"
        else:
            msg_policy_color = curses.color_pair(9)
        
        #directories
        ddir = profile.get('download_dir',"")
        if ddir == "":
            ddir = os.path.join(self.engine.get_home_dir(), "Downloads")
        # PRINT
        #PROFILE
        self.stdscr.addstr(1, 2, "PROFILE:", curses.A_BOLD)
        self.stdscr.addstr(2, 3, "  IDENT:", curses.color_pair(25))
        self.stdscr.addstr(2, 12, str(my_id), curses.color_pair(13))
        self.stdscr.addstr(3, 3, "   NICK:", curses.color_pair(25))
        self.stdscr.addstr(3, 12, profile.get('nickname', 'Anon'), curses.color_pair(13))
        self.stdscr.addstr(4, 3, "ALIASES:", curses.color_pair(25))
        self.stdscr.addstr(4, 12, str(len(profile.get('aliases', {}))), curses.color_pair(0))
        self.stdscr.addstr(5, 3, "SERVERS: ", curses.color_pair(25))
        self.stdscr.addstr(5, 12, str(len(profile.get('servers', {}))), curses.color_pair(0))
        #NETWORK
        self.stdscr.addstr(6, 2, "NETWORK:", curses.A_BOLD)
        self.stdscr.addstr(7, 3, " STATUS:", curses.color_pair(25))
        self.stdscr.addstr(7, 12, proxy_status, proxy_status_color)
        self.stdscr.addstr(8, 3, "  PROXY:", curses.color_pair(25))
        self.stdscr.addstr(8, 12, profile.get('tor_proxy', 'Unknown'), curses.color_pair(15))
        self.stdscr.addstr(9, 3, "  PEERS:", curses.color_pair(25))
        self.stdscr.addstr(9, 12, str(peer_count), curses.color_pair(0))
        #POLICY
        self.stdscr.addstr(10, 2, " POLICY:", curses.A_BOLD)
        self.stdscr.addstr(11, 3, "    MSG:", curses.color_pair(25))
        self.stdscr.addstr(11, 12, str_msg_policy, msg_policy_color)
        self.stdscr.addstr(12, 3, "   FILE:", curses.color_pair(25))
        self.stdscr.addstr(12, 12, str_file_policy, file_policy_color)
        self.stdscr.addstr(13, 3, "  LIMIT:", curses.color_pair(25))
        self.stdscr.addstr(13, 12, f"{limit} bytes", curses.color_pair(0))
        #PATHS
        self.stdscr.addstr(14, 2, "  PATHS:", curses.A_BOLD)
        self.stdscr.addstr(15, 3, "     DL:", curses.color_pair(25))
        self.stdscr.addstr(15, 12, ddir, curses.color_pair(0))
        self.stdscr.addstr(16, 3, "  VAULT:", curses.color_pair(25))
        self.stdscr.addstr(16, 12, self.engine._get_vault_path(), curses.color_pair(0))



        version = f"VERSION: {ver}"
        self.stdscr.addstr(self.height - 1, self.width - (len(version) + 1), version, curses.A_BOLD)

    def handle_input(self, key):
        if key == 27: # ESC
            #saves state rather than returning new instance
            return "BACK"