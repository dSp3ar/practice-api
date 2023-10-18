import os


class Config:
    SQLALCHEMY_DATABASE_URI = 'sqlite:///' + os.path.join(os.path.abspath(os.curdir), 'dev.db')
    SECRET_KEY = 'ewargdhijroweqpkrfndkeoprgbmnrfeowqpfrghnf'
    SECRET_APPROVAL_KEY = 'eigokrtpirsojpiogmristosriokentbioskrtnmgojk'
