import curses
import os
import time
import logging
from ui.screens import BaseScreen, LockScreen, ChatScreen, ConfigScreen

# Reduce ESC key delay to 25ms
os.environ.setdefault('ESCDELAY', '25')

class App:
    #
    # color guide COLOR GUIDE #
    #PAIRS:
    #
    #  0 = CLEAR
    #  1 = DEEP RED      9 = RED        17 = W on R
    #  2 = DEEP ORANGE  10 = ORANGE     18 = W on O
    #  3 = DEEP YELLOW  11 = YELLOW     19 = B on Y
    #  4 = DEEP GREEN   12 = GREEN      20 = B on G
    #  5 = DEEP CYAN    13 = CYAN       21 = B on C
    #  6 = DEEP BLUE    14 = BLUE       22 = W on B
    #  7 = DEEP PURPLE  15 = PURPLE     23 = W on P
    #  8 = LIGHT GREY   16 = WHITE      24 = B on W
    #                                   25 = DARK GREY
    #                                   26 = BLACK
    #                                   27 = CLR on CLR
    def __init__(self, engine):
        self.engine = engine
        self.current_screen = None
        
    def run(self):
        curses.wrapper(self._main_loop)
    def _init_colors(self):

        try:
            curses.start_color()
            if curses.can_change_color():
                curses.use_default_colors()
            #custom colors
            curses.init_pair(1, 1, -1)#r
            curses.init_pair(2, 3, -1)#o
            curses.init_pair(3, 100, -1)#y
            curses.init_pair(4, 2, -1)#g
            curses.init_pair(5, 6, -1)#c
            curses.init_pair(6, 4, -1)#b
            curses.init_pair(7, 5, -1)#p
            curses.init_pair(8, 7, -1)

            curses.init_pair(9, 9, -1)#r
            curses.init_pair(10, 202, -1)#o
            curses.init_pair(11, 11, -1)#y
            curses.init_pair(12, 10, -1)#g
            curses.init_pair(13, 14, -1)#c
            curses.init_pair(14, 21, -1)#b
            curses.init_pair(15, 13, -1)#p
            curses.init_pair(16, 15, -1)#w

            curses.init_pair(17, 15, 9)#r
            curses.init_pair(18, 15, 202)#o
            curses.init_pair(19, 16, 11)#y
            curses.init_pair(20, 16, 10)#g
            curses.init_pair(21, 16, 14)#c
            curses.init_pair(22, 15, 21)#b
            curses.init_pair(23, 15, 13)#p
            curses.init_pair(24, 16, 15)#w

            curses.init_pair(25, 8, -1)
            curses.init_pair(26, 16, -1)
            curses.init_pair(27, -1, -1)
        except curses.error:
            pass

    # GUI
    def _main_loop(self, stdscr):
        # SETUP
        self._init_colors()
        try:
            curses.curs_set(0)
        except curses.error:
            pass
        stdscr.nodelay(True)
        stdscr.timeout(50) 
        
        self.current_screen = LockScreen(stdscr, self.engine)
        needs_redraw = True

        while self.engine.running:
            oldstatus = self.engine.status_msg
            # Resizing
            if curses.is_term_resized(*stdscr.getmaxyx()):
                curses.update_lines_cols()
                self.current_screen.resize()
                stdscr.clear()
                needs_redraw = True

            # Input
            try:
                key = stdscr.getch()
                if key != -1:
                    #For mapping identification
                    #logging.debug(f"UI: getch got {key}")
                    # GLOBAL HOTKEYS
                    if key == 12: # Ctrl+L -> LOCK VAULT
                        self.engine.lock()
                        self.current_screen = LockScreen(stdscr, self.engine)
                        stdscr.clear()
                        needs_redraw = True
                    
                    # INPUT KEYS
                    else:
                        needs_redraw = True
                        new_screen = self.current_screen.handle_input(key)
                        #Switch if returned a screen
                        if isinstance(new_screen, BaseScreen):
                            old_screen = self.current_screen
                            self.current_screen = new_screen
                            self.current_screen.resize()
                            stdscr.clear()
                        elif new_screen == "BACK":
                            new_screen = old_screen
                            self.current_screen = old_screen
                            self.current_screen.resize()
                            stdscr.clear()
                        #Exit if returned QUIT
                        elif new_screen == "QUIT":
                            self.engine.running = False
            except KeyboardInterrupt:
                self.engine.shutdown()
            # Tick engine and handle UI
            self.engine.tick()
            if not self.engine.ui_queue.empty():
                while not self.engine.ui_queue.empty():
                    msg = self.engine.ui_queue.get()
                    if isinstance(msg, dict):
                        # SYSTEM PRINT
                        if "print" in msg:
                            if hasattr(self.current_screen, 'push_system_log'):
                                self.current_screen.push_system_log(msg["print"])
                        # CHAT MESSAGE
                        elif "chat" in msg:
                            data = msg["chat"]
                            if hasattr(self.current_screen, 'push_chat_message'):
                                self.current_screen.push_chat_message(
                                    sender_nick=data.get('nick', '???'),
                                    text=data.get('text', ''),
                                    timestamp=data.get('time', '--:--'),
                                    sender_color=data.get('sender_color', 11),
                                    text_color=data.get('text_color', 0)
                                )
                        # COMMANDS
                        elif "command" in msg:
                            cmd = msg["command"]
                            if cmd == "clean_logs":
                                if hasattr(self.current_screen, 'clear_non_chat'):
                                    self.current_screen.clear_non_chat()
                            if cmd == "refresh":
                                if hasattr(self.current_screen, 'refresh_view'):
                                    self.current_screen.refresh_view(msg.get("data", []))
                    needs_redraw = True
            # Draw
            if needs_redraw or self.engine.status_msg != oldstatus:
                try:
                    self.current_screen.draw()
                    stdscr.refresh()
                    needs_redraw = False 
                except curses.error:
                    pass