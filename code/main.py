from kivymd.app import MDApp
from kivy.lang import Builder
from kivymd.uix.screen import MDScreen
from kivymd.uix.boxlayout import MDBoxLayout
from kivymd.uix.navigationrail import MDNavigationRailItem
from kivy.clock import Clock
from kivy.properties import StringProperty, BooleanProperty

from sniffer_logic import Sniffer


class CommonNavigationRailItem(MDNavigationRailItem):
    text = StringProperty()
    icon = StringProperty()
    screen_to_open = StringProperty()


class SnifferScreen(MDScreen):
    def on_enter(self):
        self.packets = []
        self.sniffer = Sniffer(
            iface="eth0",
            on_packet=self.packet_thread,
        )

    def on_leave(self):
        if hasattr(self, "sniffer"):
            self.sniffer.stop()

    def start_sniffer(self):
        self.sniffer.start()

    def packet_thread(self, data):
        Clock.schedule_once(lambda dt: self.add_row(data))

    def add_row(self, data):
        self.packets.append(
            {
                "src_ip": data["src"],
                "dst_ip": data["dst"],
                "protocol": data["proto"],
                "info": data["info"],
                "length": str(data["length"]),
                "index": "",
                "timestamp": "",
            }
        )
        self.ids.packet_list.data = self.packets


class PacketRow(MDBoxLayout):
    index = StringProperty("")
    timestamp = StringProperty("")
    src_ip = StringProperty("")
    dst_ip = StringProperty("")
    protocol = StringProperty("")
    length = StringProperty("")
    info = StringProperty("")


class SenderScreen(MDScreen):
    pass


class NetworkSuiteApp(MDApp):
    capturing = BooleanProperty(False)

    def build(self):
        self.theme_cls.theme_style = "Light"
        self.theme_cls.primary_palette = "Green"
        return Builder.load_file("main.kv")

    def switch_screen(self, nameScreen):
        # Il nome della screen deve corrispondere al 'name' nel manager
        self.root.ids.screen_manager.current = nameScreen


if __name__ == "__main__":
    NetworkSuiteApp().run()
