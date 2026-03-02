from kivymd.app import MDApp
from kivy.lang import Builder
from kivymd.uix.screenmanager import MDScreenManager
from kivymd.uix.screen import MDScreen

class MenuScreen(MDScreen):
    pass

class SnifferScreen(MDScreen):
    pass

class NetworkSuiteApp(MDApp):
    def build(self):
        self.theme_cls.theme_style = "Light"
        self.theme_cls.primary_palette = "Purple"
        
        return Builder.load_file("main.kv")

if __name__ == "__main__":
    NetworkSuiteApp().run()