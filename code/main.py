from kivymd.app import MDApp
from kivy.lang import Builder
from kivymd.uix.screen import MDScreen
from kivymd.uix.behaviors import HoverBehavior
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
    index = 1
    capturing = BooleanProperty(False)
    filters = StringProperty("")
    filtersList = []

    def on_enter(self):
        self.packets = []
        self.sniffer = Sniffer(
            bpf_filter=self.filters,
            on_packet=self.packet_thread,
        )

    def on_leave(self):
        if hasattr(self, "sniffer"):
            self.sniffer.stop()

    def start_sniffer(self):
        self.capturing = True
        self.sniffer.start()

    def stop_sniffer(self):
        self.capturing = False
        self.sniffer.stop()

    def clear(self):
        self.packets = []
        self.ids.packet_list.data = self.packets
        self.index = 1

    def packet_thread(self, data):
        Clock.schedule_once(lambda dt: self.add_row(data))

    def add_row(self, data):
        self.packets.append(
            {
                "index": str(self.index),
                "src_ip": data["src"],
                "dst_ip": data["dst"],
                "protocol": data["proto"],
                "info": data["info"],
                "length": str(data["length"]),
                "timestamp": "",
            }
        )
        self.index += 1
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

        self.sniffer.bpf_filter = self.filters
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
        self.md_bg_color = "lightgreen"
    
    def on_leave(self):
        self.md_bg_color = "white"


class InfoPacketScreen(MDScreen):
    pass


class SenderScreen(MDScreen):
    pass


class NetworkSuiteApp(MDApp):
    def build(self):
        self.theme_cls.theme_style = "Light"
        self.theme_cls.primary_palette = "Green"
        return Builder.load_file("main.kv")

    def switch_screen(self, nameScreen):
        # Il nome della screen deve corrispondere al 'name' nel manager
        self.root.ids.screen_manager.current = nameScreen


if __name__ == "__main__":
    NetworkSuiteApp().run()
