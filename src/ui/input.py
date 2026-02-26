import curses

# Text input box
class TextInput:
    """ should draw last"""
    def __init__(self, prompt=">> ", draw_cursor=False, password=False):
        self.prompt = prompt
        self.password = password
        self.draw_cursor = draw_cursor
        self.buffer = []
        self.cursor_idx = 0
        # Internal History
        self.history = []
        self.history_idx = -1 
        self.temp_buffer = []

    def get_text(self) -> str:
        return "".join(self.buffer)

    def reset(self):
        self.buffer = []
        self.cursor_idx = 0
        self.history_idx = -1
        self.temp_buffer = []

    def handle_key(self, key: int) -> str | bool:
        """
        Returns:
            str: The final command string if 'Enter' was pressed.
            True: If the key was functional (history, arrows, backspace, etc.)
            False: If ignored.
        """
        # ENTER
        if key in (10, 13, curses.KEY_ENTER):
            command = self.get_text()
            if not self.password and command.strip():
                self.history.append(list(command))
            return command 
        # BACKSPACE
        if key in (curses.KEY_BACKSPACE, 127, 8):
            if self.cursor_idx > 0:
                self.buffer.pop(self.cursor_idx - 1)
                self.cursor_idx -= 1
            return True
        # CTRL + UP (History Previous) (Not for passwds)
        elif (key in (566, 521, 547, 571, 575)) and not self.password:
            if self.history:
                if self.history_idx == -1:
                    self.temp_buffer = list(self.buffer)
                
                if self.history_idx < len(self.history) - 1:
                    self.history_idx += 1
                    self.buffer = list(self.history[-(self.history_idx + 1)])
                    self.cursor_idx = len(self.buffer)
            return True
        # CTRL + DOWN (History Next) (Not for passwds)
        elif (key in (527, 514, 548, 530, 534)) and not self.password:
            if self.history_idx > 0:
                self.history_idx -= 1
                self.buffer = list(self.history[-(self.history_idx + 1)])
                self.cursor_idx = len(self.buffer)
            elif self.history_idx == 0:
                self.history_idx = -1
                self.buffer = list(self.temp_buffer)
                self.cursor_idx = len(self.buffer)
            return True
        # Cursor movement
        elif key == curses.KEY_LEFT:
            if self.cursor_idx > 0: self.cursor_idx -= 1
            return True
        elif key == curses.KEY_RIGHT:
            if self.cursor_idx < len(self.buffer): self.cursor_idx += 1
            return True
        # Standard keys
        elif 32 <= key <= 126:
            self.buffer.insert(self.cursor_idx, chr(key))
            self.cursor_idx += 1
            self.history_idx = -1 
            return True
        return False

    def draw(self, window, y, x, width, prompt_color=0, text_color=0, ps1_colors=[0,0,0,0]):
        text_start_x = x + len(self.prompt)
        visible_width = width - len(self.prompt) - 1
        
        if not self.password and self.draw_cursor:
            curses.curs_set(1)
        try:
            # Draw Prompt
            if ps1_colors == [0,0,0,0]:
                window.addstr(y, x, self.prompt, curses.color_pair(prompt_color))
            else:
                pss = ["","","",""]
                pss[0], pss[1], end = self.prompt.partition("@")
                pss[2] = end[:5]
                pss[3] = end[5:]
                curx = x
                for i in range(4):
                    window.addstr(y, curx, pss[i], curses.color_pair(ps1_colors[i]) | curses.A_BOLD)
                    curx += len(pss[i])


            # Mask if password
            raw_text = "*" * len(self.buffer) if self.password else "".join(self.buffer)
            # Scrolling logic if input is longer than window
            offset = 0
            if self.cursor_idx >= visible_width:
                offset = self.cursor_idx - visible_width + 1
            display_text = raw_text[offset : offset + visible_width]
            window.addstr(y, text_start_x, display_text, curses.color_pair(text_color))
            # Move cursor to correct position
            window.move(y, text_start_x + (self.cursor_idx - offset))

        except curses.error:
            pass

# Multi-colored lines
class RichLine:
    """Represents a single log line with multiple color segments."""
    def __init__(self, segments=None, is_chat=False):
        # segments are a list of (color_pair_id, text)
        self.segments = segments or []
        self.is_chat = is_chat
    
    def clear(self):
        self.segments = []

    def add(self, color_id, text):
        self.segments.append((color_id, text))
        return self

    def __repr__(self):
        return "".join(s[1] for s in self.segments)