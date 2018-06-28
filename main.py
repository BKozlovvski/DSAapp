#!/usr/bin/env python
# -*- coding: utf-8 -*-

import os
import sys
from PyQt4 import QtGui, QtCore
from PyQt4.QtGui import QApplication
from PyQt4.QtCore import QFileInfo
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import dsa
from cryptography.hazmat.primitives.asymmetric import utils


BUFFER_SIZE = 65536


class Window(QtGui.QMainWindow):
    def __init__(self):
        super(Window, self).__init__()
        self.filePath = ''
        self.keyPath = ''
        self.signaturePath = ''
        self.outcomeLabel = QtGui.QLabel()
        self.filePathBox = QtGui.QTextEdit()
        self.keyPathBox = QtGui.QTextEdit()
        self.sigPathBox = QtGui.QTextEdit()
        self.resolution = QtGui.QDesktopWidget().screenGeometry()
        self.center = []
        self.setWindowIcon(QtGui.QIcon(''))
        self.setWindowFlags(QtCore.Qt.WindowMinimizeButtonHint)
        self.startWindow()

    def startWindow(self):
        self.setGeometry(0, 0, 500, 100)
        self.center = (self.resolution.width() / 2) - (self.frameSize().width() / 2),\
                      (self.resolution.height() / 2) - (self.frameSize().height() / 2)
        self.move(self.center[0], self.center[1])
        self.setWindowTitle("Simple Digital Signer - Choose what do you want to do:")

        gridLayout = QtGui.QGridLayout()

        signModeBtn = QtGui.QPushButton("Sign file")
        signModeBtn.clicked.connect(self.signMode)
        gridLayout.addWidget(signModeBtn, 0, 0)

        validModeBtn = QtGui.QPushButton("Validate signed file")
        validModeBtn.clicked.connect(self.validationMode)
        gridLayout.addWidget(validModeBtn, 1, 0)

        quitBtn = QtGui.QPushButton("Quit", self)
        quitBtn.clicked.connect(self.closeApp)
        gridLayout.addWidget(quitBtn, 2, 0)

        centralWidget = QtGui.QWidget()
        centralWidget.setLayout(gridLayout)
        self.setCentralWidget(centralWidget)
        self.show()

    def signMode(self):
        self.filePath = ''
        self.keyPath = ''
        self.signaturePath = ''
        self.setGeometry(0, 0, 600, 200)
        self.center = (self.resolution.width() / 2) - (self.frameSize().width() / 2),\
                      (self.resolution.height() / 2) - (self.frameSize().height() / 2)
        self.move(self.center[0], self.center[1])
        self.setWindowTitle("Simple Digital Signer - File signing mode")

        gridLayout = QtGui.QGridLayout()

        stepOneLabel1 = QtGui.QLabel("Step 1 - Select private key:")
        gridLayout.addWidget(stepOneLabel1, 0, 0)

        useExistingKeyBtn = QtGui.QPushButton("Use existing key", self)
        useExistingKeyBtn.clicked.connect(self.selectKey)
        gridLayout.addWidget(useExistingKeyBtn, 0, 1)

        stepOneLabel = QtGui.QLabel("or")
        stepOneLabel.setAlignment(QtCore.Qt.AlignCenter)
        gridLayout.addWidget(stepOneLabel, 0, 2)

        createKeyBtn = QtGui.QPushButton("Create new key", self)
        createKeyBtn.clicked.connect(self.createNewKey)
        gridLayout.addWidget(createKeyBtn, 0, 3)

        stepTwoLabel = QtGui.QLabel("Key file path:")
        gridLayout.addWidget(stepTwoLabel, 1, 0)

        self.keyPathBox.setReadOnly(True)
        self.keyPathBox.setText(self.keyPath)
        self.keyPathBox.setMaximumHeight(24)
        gridLayout.addWidget(self.keyPathBox, 1, 1, 1, 3)

        stepThreeLabel = QtGui.QLabel("Step 3 - select file to sign:")
        gridLayout.addWidget(stepThreeLabel, 2, 0)

        self.filePathBox.setReadOnly(True)
        self.filePathBox.setText(self.filePath)
        self.filePathBox.setMaximumHeight(24)
        gridLayout.addWidget(self.filePathBox, 2, 1, 1, 2)

        browseBtn = QtGui.QPushButton("Browse", self)
        browseBtn.clicked.connect(self.selectFile)
        gridLayout.addWidget(browseBtn, 2, 3)

        stepFourLabel = QtGui.QLabel("Step 4 - sign the file:")
        gridLayout.addWidget(stepFourLabel, 3, 0)

        signBtn = QtGui.QPushButton("Sign file!", self)
        signBtn.clicked.connect(self.signFile)
        gridLayout.addWidget(signBtn, 3, 1, 1, 3)

        stepFiveLabel = QtGui.QLabel("Step 5 - Outcome:")
        gridLayout.addWidget(stepFiveLabel, 4, 0)

        self.outcomeLabel.setText("Not signed!")
        gridLayout.addWidget(self.outcomeLabel, 4, 1)

        changeModeBtn = QtGui.QPushButton("Validation mode", self)
        changeModeBtn.clicked.connect(self.changeModeToValidation)
        gridLayout.addWidget(changeModeBtn, 5, 1)

        quitBtn = QtGui.QPushButton("Quit", self)
        quitBtn.clicked.connect(self.closeApp)
        gridLayout.addWidget(quitBtn, 5, 3)

        centralWidget = QtGui.QWidget()
        centralWidget.setLayout(gridLayout)
        self.setCentralWidget(centralWidget)
        self.show()

    def validationMode(self):
        self.filePath = ''
        self.keyPath = ''
        self.signaturePath = ''

        self.setGeometry(0, 0, 600, 200)
        self.center = (self.resolution.width() / 2) - (self.frameSize().width() / 2),\
                      (self.resolution.height() / 2) - (self.frameSize().height() / 2)
        self.move(self.center[0], self.center[1])
        self.setWindowTitle("Simple Digital Signer - Sign validation mode")

        gridLayout = QtGui.QGridLayout()

        stepOneLabel = QtGui.QLabel("Step 1 - Select public key:")
        gridLayout.addWidget(stepOneLabel, 0, 0)

        self.keyPathBox.setReadOnly(True)
        self.keyPathBox.setText(self.keyPath)
        self.keyPathBox.setMaximumHeight(24)
        gridLayout.addWidget(self.keyPathBox, 0, 1)

        browseBtn = QtGui.QPushButton("Browse", self)
        browseBtn.clicked.connect(self.selectKey)
        gridLayout.addWidget(browseBtn, 0, 2)

        stepTwoLabel = QtGui.QLabel("Step 2 - Select file:")
        gridLayout.addWidget(stepTwoLabel, 1, 0)

        self.filePathBox.setReadOnly(True)
        self.filePathBox.setText(self.filePath)
        self.filePathBox.setMaximumHeight(24)
        gridLayout.addWidget(self.filePathBox, 1, 1)

        browseBtn = QtGui.QPushButton("Browse", self)
        browseBtn.clicked.connect(self.selectFile)
        gridLayout.addWidget(browseBtn, 1, 2)

        stepTwoLabel = QtGui.QLabel("Step 3 - Select signature file:")
        gridLayout.addWidget(stepTwoLabel, 2, 0)

        self.sigPathBox.setReadOnly(True)
        self.sigPathBox.setText(self.signaturePath)
        self.sigPathBox.setMaximumHeight(24)
        gridLayout.addWidget(self.sigPathBox, 2, 1)

        browseBtn = QtGui.QPushButton("Browse", self)
        browseBtn.clicked.connect(self.selectSignature)
        gridLayout.addWidget(browseBtn, 2, 2)

        stepThreeLabel = QtGui.QLabel("Step 4 - Validate signature:")
        gridLayout.addWidget(stepThreeLabel, 3, 0)

        validateBtn = QtGui.QPushButton("Validate!", self)
        validateBtn.clicked.connect(self.validateFile)
        gridLayout.addWidget(validateBtn, 3, 1, 1, 2)

        stepFiveLabel = QtGui.QLabel("Step 5 - Outcome:")
        gridLayout.addWidget(stepFiveLabel, 4, 0)

        self.outcomeLabel.setText("Not validated!")
        gridLayout.addWidget(self.outcomeLabel, 4, 1)

        changeModeBtn = QtGui.QPushButton("Signing mode", self)
        changeModeBtn.clicked.connect(self.changeModeToSign)
        gridLayout.addWidget(changeModeBtn, 5, 1)

        quitBtn = QtGui.QPushButton("Quit", self)
        quitBtn.clicked.connect(self.closeApp)
        gridLayout.addWidget(quitBtn, 5, 2)

        centralWidget = QtGui.QWidget()
        centralWidget.setLayout(gridLayout)
        self.setCentralWidget(centralWidget)
        self.show()

    def changeModeToSign(self):
        choice = QtGui.QMessageBox.question(self, 'Change mode?', "Are you sure you want to change the mode?",
                                            QtGui.QMessageBox.Yes | QtGui.QMessageBox.No)
        if choice == QtGui.QMessageBox.Yes:
            self.signMode()
        else:
            pass

    def changeModeToValidation(self):
        choice = QtGui.QMessageBox.question(self, 'Change mode?', "Are you sure you want to change the mode?",
                                            QtGui.QMessageBox.Yes | QtGui.QMessageBox.No)
        if choice == QtGui.QMessageBox.Yes:
            self.validationMode()
        else:
            pass

    def selectFile(self):
        self.filePath = QtGui.QFileDialog.getOpenFileName(self, 'Open file', os.getcwd())
        self.filePathBox.setText(self.filePath)
        QtGui.QApplication.processEvents()

    def selectKey(self):
        self.keyPath = QtGui.QFileDialog.getOpenFileName(self, 'Select key file', os.getcwd(), '*.pem')
        self.keyPathBox.setText(self.keyPath)
        QtGui.QApplication.processEvents()

    def selectSignature(self):
        self.signaturePath = QtGui.QFileDialog.getOpenFileName(self, 'Select signature file', os.getcwd(), '*.sig')
        self.sigPathBox.setText(self.signaturePath)
        QtGui.QApplication.processEvents()

    def signFile(self):
        if self.filePath == '':
            QtGui.QMessageBox.information(self, 'Error!', "Please select the file!",
                                          QtGui.QMessageBox.Ok)
        elif self.keyPath == '':
            QtGui.QMessageBox.information(self, 'Error!', "Please select the key to proceed!",
                                          QtGui.QMessageBox.Ok)
        else:
            self.sign()

    def validateFile(self):
        if self.keyPath == '':
            QtGui.QMessageBox.information(self, 'Error!', "Please select the key to proceed!",
                                          QtGui.QMessageBox.Ok)
        elif self.filePath == '':
            QtGui.QMessageBox.information(self, 'Error!', "Please select the file!",
                                          QtGui.QMessageBox.Ok)
        elif self.signaturePath == '':
            QtGui.QMessageBox.information(self, 'Error!', "Please select the signature file to proceed!",
                                          QtGui.QMessageBox.Ok)
        else:
            self.validate()

    def createNewKey(self):
        choice = QtGui.QMessageBox.question(self, 'Generate new keys?', "Are you sure you want to generate new set of keys "
                                                           "(private and public)?",
                                            QtGui.QMessageBox.Yes | QtGui.QMessageBox.No)
        if choice == QtGui.QMessageBox.Yes:
            key = dsa.generate_private_key(3072, backend=default_backend())       # TODO Dorobic wybor dugosci klucza
            try:
                with open("privateKey.pem", "wb") as f:
                    f.write(key.private_bytes(encoding=serialization.Encoding.PEM,
                                                  format=serialization.PrivateFormat.TraditionalOpenSSL,
                                                  encryption_algorithm=serialization.NoEncryption(),))

                    # f.write(key.private_bytes(encoding=serialization.Encoding.PEM,
                    #                           format=serialization.PrivateFormat.TraditionalOpenSSL,
                    #                           encryption_algorithm=serialization.BestAvailableEncryption(b"password"),))

                    QtGui.QMessageBox.information(self, 'Success!', "New key generated successfully!",
                                                  QtGui.QMessageBox.Ok)
                self.keyPath = os.path.abspath(f.name)
                self.keyPathBox.setText(self.keyPath)
                QtGui.QApplication.processEvents()
            except IOError:
                QtGui.QMessageBox.critical(self, 'Error!', "Key generation failed!", QtGui.QMessageBox.Ok)
        else:
            pass

    def sign(self):
        try:
            chosen_hash = hashes.SHA256()
            hasher = hashes.Hash(chosen_hash, default_backend())
            try:
                with open(self.keyPath, "rb") as key_file:
                    private_key = serialization.load_pem_private_key(key_file.read(), password=None, backend=default_backend())
            except IOError:
                QtGui.QMessageBox.critical(self, 'Error!', "Opening key file failed!", QtGui.QMessageBox.Ok)
            try:
                with open(self.filePath, 'rb') as f:
                    info = QFileInfo(self.filePath)
                    while True:
                        data = f.read(BUFFER_SIZE)
                        if not data:
                            break
                        hasher.update(data)
            except IOError:
                QtGui.QMessageBox.critical(self, 'Error!', "Opening file to sign has failed!", QtGui.QMessageBox.Ok)

            digest = hasher.finalize()
            signature = private_key.sign(digest, utils.Prehashed(chosen_hash))
            public_key = private_key.public_key()
            public_key.verify(signature, digest, utils.Prehashed(chosen_hash))

            try:
                with open("publicKey.pem", "wb") as f:
                    serialized_public = public_key.public_bytes(encoding=serialization.Encoding.PEM,
                                                                format=serialization.PublicFormat.SubjectPublicKeyInfo)
                    f.write(serialized_public)
            except IOError:
                QtGui.QMessageBox.critical(self, 'Error!', "Saving the public key has failed!", QtGui.QMessageBox.Ok)

            try:
                with open(info.baseName()+"_signed.sig", "wb") as f:
                    f.write(signature)
            except IOError:
                QtGui.QMessageBox.critical(self, 'Error!', "Saving the signature of the file has failed!", QtGui.QMessageBox.Ok)

            self.outcomeLabel.setText("Sign successful!")
            QtGui.QApplication.processEvents()
            QtGui.QMessageBox.information(self, 'Success!', "File has been signed successfully!")
        except:
            self.outcomeLabel.setText("Signing unsuccessful!")
            QtGui.QApplication.processEvents()
            QtGui.QMessageBox.warning(self, 'Failure!', "File has not been signed successfully!")


    def validate(self):
        try:
            with open(self.keyPath, "rb") as key_file:
                public_key = serialization.load_pem_public_key(key_file.read(), backend=default_backend())
        except IOError:
            QtGui.QMessageBox.critical(self, 'Error!', "Opening key file failed!", QtGui.QMessageBox.Ok)

        try:
            with open(self.signaturePath, "rb") as signature_file:
                signature = signature_file.read()
        except IOError:
            QtGui.QMessageBox.critical(self, 'Error!', "Opening signature file failed!", QtGui.QMessageBox.Ok)

        chosen_hash = hashes.SHA256()
        hasher = hashes.Hash(chosen_hash, default_backend())
        try:
            with open(self.filePath, 'rb') as f:
                while True:
                    data = f.read(BUFFER_SIZE)
                    if not data:
                        break
                    hasher.update(data)
        except IOError:
            QtGui.QMessageBox.critical(self, 'Error!', "Opening file to validate has failed!", QtGui.QMessageBox.Ok)

        digest = hasher.finalize()
        try:
            public_key.verify(signature, digest, utils.Prehashed(chosen_hash))
            self.outcomeLabel.setText("Validation successful!")
            QtGui.QApplication.processEvents()
            QtGui.QMessageBox.information(self, 'Success!', "File has been validated successfully!")
        except:
            self.outcomeLabel.setText("Validation unsuccessful!")
            QtGui.QApplication.processEvents()
            QtGui.QMessageBox.warning(self, 'Failure!', "File has not been validated successfully!")

    def closeApp(self):
        choice = QtGui.QMessageBox.question(self, 'Quit?', "Are you sure you want to quit?",
                                            QtGui.QMessageBox.Yes | QtGui.QMessageBox.No)
        if choice == QtGui.QMessageBox.Yes:
            sys.exit()
        else:
            pass


def runApp():
    app = QtGui.QApplication(sys.argv)
    gui = Window()
    sys.exit(app.exec_())


runApp()


"""C:\Python27\python.exe C:/Users/syfee/PycharmProjects/DigitalSig/main.py
Traceback (most recent call last):
  File "C:/Users/syfee/PycharmProjects/DigitalSig/main.py", line 221, in changeModeToValidation
    self.validationMode()
  File "C:/Users/syfee/PycharmProjects/DigitalSig/main.py", line 174, in validationMode
    self.sigPathBox.setReadOnly(True)
RuntimeError: wrapped C/C++ object of type QTextEdit has been deleted
"""
