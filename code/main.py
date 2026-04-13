import datetime

from kivymd.app import MDApp
from kivy.lang import Builder
from kivymd.uix.screen import MDScreen
from kivymd.uix.behaviors import HoverBehavior
from kivymd.uix.boxlayout import MDBoxLayout
from kivymd.uix.navigationbar import MDNavigationItem
from kivymd.uix.label import MDLabel
from kivy.clock import Clock
from kivy.properties import StringProperty, BooleanProperty

from sniffer_logic import Sniffer


class CommonNavItem(MDNavigationItem):
    icon = StringProperty()
    text = StringProperty()
    screen_name = StringProperty()


class SnifferScreen(MDScreen):
    index = 1
    capturing = BooleanProperty(False)
    filters = StringProperty("")
    filtersList = []

    def on_enter(self):
        self.app = MDApp.get_running_app()
        self.packets = []
        self.app.sniffer = Sniffer(
            bpf_filter=self.filters,
            on_packet=self.packet_thread,
        )

    def on_leave(self):
        if hasattr(self, "sniffer"):
            self.app.sniffer.stop()

    def start_sniffer(self):
        self.capturing = True
        self.app.sniffer.start()

    def stop_sniffer(self):
        self.capturing = False
        self.app.sniffer.stop()

    def clear(self):
        self.packets = []
        self.ids.packet_list.data = self.packets
        self.app.sniffer.index = 0

    def packet_thread(self, data):
        Clock.schedule_once(lambda dt: self.add_row(data))

    def add_row(self, data):
        self.packets.append(
            {
                "index": data["index"],
                "src_ip": data["src"],
                "dst_ip": data["dst"],
                "protocol": data["proto"],
                "info": data["info"],
                "length": str(data["length"]),
                "timestamp": str(datetime.datetime.now()),
            }
        )
        self.ids.packet_list.data = self.packets
        self.ids.packet_list.scroll_y = 0

    def add_remove_filter(self, filter):
        self.filters = ""

        if filter not in self.filtersList:
            self.filtersList.append(filter)
        else:
            self.filtersList.remove(filter)

        for filter in self.filtersList:
            if len(self.filters) == 0:
                self.filters += filter
            else:
                self.filters += f" or {filter}"

        self.app.sniffer.bpf_filter = self.filters
        print(self.filtersList)
        print(self.filters)


class PacketRow(MDBoxLayout, HoverBehavior):
    index = StringProperty("")
    timestamp = StringProperty("")
    src_ip = StringProperty("")
    dst_ip = StringProperty("")
    protocol = StringProperty("")
    length = StringProperty("")
    info = StringProperty("")

    def on_enter(self):  # mouse sopra
        self._original_color = self.md_bg_color
        self.md_bg_color = "lightgreen"

    def on_leave(self):
        self.md_bg_color = self._original_color

    def on_touch_up(self, touch):
        if self.collide_point(*touch.pos) and not touch.is_mouse_scrolling:
            app = MDApp.get_running_app()
            screen = app.root.ids.screen_manager.get_screen("info")
            screen.load_packet(self.index)
            app.switch_screen("info")
            app.sniffer.stop()


class InfoPacketScreen(MDScreen):
    def load_packet(self, index):
        self.ids.layer_container.clear_widgets()
        app = MDApp.get_running_app()
        data = app.sniffer.selectSinglePacket(index)

        if data is None:
            return

        # Una sezione per ogni layer
        sections = {
            "ETHERNET": ["eth_src", "eth_dst"],
            "IP":       ["ip_src", "ip_dst", "ip_ttl", "ip_proto"],
            "TCP":      ["tcp_sport", "tcp_dport", "tcp_flags", "tcp_seq"],
            "UDP":      ["udp_sport", "udp_dport", "udp_len"],
            "RAW":      ["raw_hex", "raw_text"],
        }

        for section, keys in sections.items():
            # Controlla se almeno una chiave esiste nel risultato
            if not any(k in data for k in keys):
                continue

            # Titolo sezione
            self.ids.layer_container.add_widget(
                MDLabel(
                    text=f"[ {section} ]",
                    adaptive_height=True,
                    bold=True,
                    theme_text_color="Custom",
                    text_color="#00FF41",
                )
            )

            # Righe chiave: valore
            for k in keys:
                if k in data:
                    self.ids.layer_container.add_widget(
                        MDLabel(
                            text=f"  {k.split('_', 1)[1].upper():<12} {data[k]}",
                            adaptive_height=True,
                            theme_text_color="Custom",
                            text_color="#D4F5D4",
                        )
                    )


class SenderScreen(MDScreen):
    pass


class NetworkSuiteApp(MDApp):

    def on_tab_switch(self, nav_bar, item, item_icon, item_label):
        if item.screen_name != "info":
            self.root.ids.screen_manager.current = item.screen_name

    def build(self):
        self.sniffer = None
        self.theme_cls.theme_style = "Light"
        self.theme_cls.primary_palette = "Green"
        return Builder.load_file("main.kv")

    def switch_screen(self, name):
        self.root.ids.screen_manager.current = name


if __name__ == "__main__":
    NetworkSuiteApp().run()
