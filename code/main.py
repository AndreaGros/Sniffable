import datetime

from kivymd.app import MDApp
from kivy.lang import Builder
from kivymd.uix.screen import MDScreen
from kivymd.uix.behaviors import HoverBehavior
from kivymd.uix.boxlayout import MDBoxLayout
from kivymd.uix.navigationrail import MDNavigationRailItem
from kivymd.uix.label import MDLabel
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
        lbl = MDLabel(text=index)
        self.ids.layer_container.add_widget(lbl)
        app = MDApp.get_running_app()
        print(app.sniffer.selectSinglePacket(index))


class SenderScreen(MDScreen):
    pass


class NetworkSuiteApp(MDApp):
    def build(self):
        self.sniffer = None
        self.theme_cls.theme_style = "Light"
        self.theme_cls.primary_palette = "Green"
        return Builder.load_file("main.kv")

    def switch_screen(self, nameScreen):
        # Il nome della screen deve corrispondere al 'name' nel manager
        self.root.ids.screen_manager.current = nameScreen


if __name__ == "__main__":
    NetworkSuiteApp().run()
