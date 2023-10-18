from flask_admin import AdminIndexView

class MyAdminIndexView(AdminIndexView):

    def is_visible(self):
        # Этот код скрывает вкладку "Home" в панели администратора
        return False

