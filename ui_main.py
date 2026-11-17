# -*- coding: utf-8 -*-

################################################################################
## Form generated from reading UI file 'main.ui'
##
## Created by: Qt User Interface Compiler version 6.12.0
##
## WARNING! All changes made in this file will be lost when recompiling UI file!
################################################################################

from PySide6.QtCore import (QCoreApplication, QDate, QDateTime, QLocale,
    QMetaObject, QObject, QPoint, QRect,
    QSize, QTime, QUrl, Qt)
from PySide6.QtGui import (QBrush, QColor, QConicalGradient, QCursor,
    QFont, QFontDatabase, QGradient, QIcon,
    QImage, QKeySequence, QLinearGradient, QPainter,
    QPalette, QPixmap, QRadialGradient, QTransform)
from PySide6.QtWidgets import (QApplication, QComboBox, QHBoxLayout, QHeaderView,
    QLabel, QLineEdit, QPlainTextEdit, QSizePolicy,
    QTableWidget, QTableWidgetItem, QToolButton, QTreeWidget,
    QTreeWidgetItem, QVBoxLayout, QWidget)
import res_rc

class Ui_MiniWireShark(object):
    def setupUi(self, MiniWireShark):
        if not MiniWireShark.objectName():
            MiniWireShark.setObjectName(u"MiniWireShark")
        MiniWireShark.resize(740, 705)
        self.verticalLayout_3 = QVBoxLayout(MiniWireShark)
        self.verticalLayout_3.setObjectName(u"verticalLayout_3")
        self.horizontalLayout = QHBoxLayout()
        self.horizontalLayout.setObjectName(u"horizontalLayout")
        self.labelIface = QLabel(MiniWireShark)
        self.labelIface.setObjectName(u"labelIface")

        self.horizontalLayout.addWidget(self.labelIface)

        self.ifaceCombo = QComboBox(MiniWireShark)
        self.ifaceCombo.setObjectName(u"ifaceCombo")
        self.ifaceCombo.setMinimumSize(QSize(240, 0))

        self.horizontalLayout.addWidget(self.ifaceCombo)

        self.btnStart = QToolButton(MiniWireShark)
        self.btnStart.setObjectName(u"btnStart")
        icon = QIcon()
        icon.addFile(u":/icons/start.svg", QSize(), QIcon.Mode.Normal, QIcon.State.Off)
        self.btnStart.setIcon(icon)
        self.btnStart.setIconSize(QSize(24, 24))

        self.horizontalLayout.addWidget(self.btnStart)

        self.btnStop = QToolButton(MiniWireShark)
        self.btnStop.setObjectName(u"btnStop")
        icon1 = QIcon()
        icon1.addFile(u":/icons/stop.svg", QSize(), QIcon.Mode.Normal, QIcon.State.Off)
        self.btnStop.setIcon(icon1)
        self.btnStop.setIconSize(QSize(24, 24))

        self.horizontalLayout.addWidget(self.btnStop)

        self.btnRestart = QToolButton(MiniWireShark)
        self.btnRestart.setObjectName(u"btnRestart")
        icon2 = QIcon()
        icon2.addFile(u":/icons/restart.svg", QSize(), QIcon.Mode.Normal, QIcon.State.Off)
        self.btnRestart.setIcon(icon2)
        self.btnRestart.setIconSize(QSize(24, 24))

        self.horizontalLayout.addWidget(self.btnRestart)

        self.btnSave = QToolButton(MiniWireShark)
        self.btnSave.setObjectName(u"btnSave")
        icon3 = QIcon()
        icon3.addFile(u":/icons/save.svg", QSize(), QIcon.Mode.Normal, QIcon.State.Off)
        self.btnSave.setIcon(icon3)
        self.btnSave.setIconSize(QSize(24, 24))

        self.horizontalLayout.addWidget(self.btnSave)

        self.btnOpen = QToolButton(MiniWireShark)
        self.btnOpen.setObjectName(u"btnOpen")
        icon4 = QIcon()
        icon4.addFile(u":/icons/open.svg", QSize(), QIcon.Mode.Normal, QIcon.State.Off)
        self.btnOpen.setIcon(icon4)
        self.btnOpen.setIconSize(QSize(24, 24))

        self.horizontalLayout.addWidget(self.btnOpen)

        self.btnFlow = QToolButton(MiniWireShark)
        self.btnFlow.setObjectName(u"btnFlow")
        icon5 = QIcon()
        icon5.addFile(u":/icons/flow.svg", QSize(), QIcon.Mode.Normal, QIcon.State.Off)
        self.btnFlow.setIcon(icon5)
        self.btnFlow.setIconSize(QSize(24, 24))

        self.horizontalLayout.addWidget(self.btnFlow)

        self.btnRoute = QToolButton(MiniWireShark)
        self.btnRoute.setObjectName(u"btnRoute")
        icon6 = QIcon()
        icon6.addFile(u":/icons/route.svg", QSize(), QIcon.Mode.Normal, QIcon.State.Off)
        self.btnRoute.setIcon(icon6)
        self.btnRoute.setIconSize(QSize(24, 24))

        self.horizontalLayout.addWidget(self.btnRoute)


        self.verticalLayout_3.addLayout(self.horizontalLayout)

        self.horizontalLayout_2 = QHBoxLayout()
        self.horizontalLayout_2.setObjectName(u"horizontalLayout_2")
        self.inputFilter = QLineEdit(MiniWireShark)
        self.inputFilter.setObjectName(u"inputFilter")

        self.horizontalLayout_2.addWidget(self.inputFilter)


        self.verticalLayout_3.addLayout(self.horizontalLayout_2)

        self.verticalLayout_2 = QVBoxLayout()
        self.verticalLayout_2.setObjectName(u"verticalLayout_2")
        self.showPacketTable = QTableWidget(MiniWireShark)
        self.showPacketTable.setObjectName(u"showPacketTable")

        self.verticalLayout_2.addWidget(self.showPacketTable)

        self.horizontalLayout_3 = QHBoxLayout()
        self.horizontalLayout_3.setObjectName(u"horizontalLayout_3")
        self.packetInfo = QTreeWidget(MiniWireShark)
        __qtreewidgetitem = QTreeWidgetItem()
        __qtreewidgetitem.setText(0, u"1")
        self.packetInfo.setHeaderItem(__qtreewidgetitem)
        self.packetInfo.setObjectName(u"packetInfo")

        self.horizontalLayout_3.addWidget(self.packetInfo)

        self.hexView = QPlainTextEdit(MiniWireShark)
        self.hexView.setObjectName(u"hexView")

        self.horizontalLayout_3.addWidget(self.hexView)


        self.verticalLayout_2.addLayout(self.horizontalLayout_3)


        self.verticalLayout_3.addLayout(self.verticalLayout_2)


        self.retranslateUi(MiniWireShark)

        QMetaObject.connectSlotsByName(MiniWireShark)
    # setupUi

    def retranslateUi(self, MiniWireShark):
        MiniWireShark.setWindowTitle(QCoreApplication.translate("MiniWireShark", u"Form", None))
        self.labelIface.setText(QCoreApplication.translate("MiniWireShark", u"\uc778\ud130\ud398\uc774\uc2a4", None))
#if QT_CONFIG(tooltip)
        self.ifaceCombo.setToolTip(QCoreApplication.translate("MiniWireShark", u"\ucea1\ucc98\ud560 \ub124\ud2b8\uc6cc\ud06c \uc778\ud130\ud398\uc774\uc2a4 (\ucea1\ucc98 \uc911\uc5d0\ub294 \ubabb \ubc14\uafc8)", None))
#endif // QT_CONFIG(tooltip)
#if QT_CONFIG(tooltip)
        self.btnStart.setToolTip(QCoreApplication.translate("MiniWireShark", u"\ucea1\ucc98 \uc2dc\uc791", None))
#endif // QT_CONFIG(tooltip)
        self.btnStart.setText(QCoreApplication.translate("MiniWireShark", u"...", None))
#if QT_CONFIG(tooltip)
        self.btnStop.setToolTip(QCoreApplication.translate("MiniWireShark", u"\ucea1\ucc98 \uc815\uc9c0", None))
#endif // QT_CONFIG(tooltip)
        self.btnStop.setText(QCoreApplication.translate("MiniWireShark", u"...", None))
#if QT_CONFIG(tooltip)
        self.btnRestart.setToolTip(QCoreApplication.translate("MiniWireShark", u"\uc7ac\uc2dc\uc791 (\ud45c \ube44\uc6b0\uae30)", None))
#endif // QT_CONFIG(tooltip)
        self.btnRestart.setText(QCoreApplication.translate("MiniWireShark", u"...", None))
#if QT_CONFIG(tooltip)
        self.btnSave.setToolTip(QCoreApplication.translate("MiniWireShark", u"pcap \uc800\uc7a5", None))
#endif // QT_CONFIG(tooltip)
        self.btnSave.setText(QCoreApplication.translate("MiniWireShark", u"...", None))
#if QT_CONFIG(tooltip)
        self.btnOpen.setToolTip(QCoreApplication.translate("MiniWireShark", u"pcap \ubd88\ub7ec\uc624\uae30", None))
#endif // QT_CONFIG(tooltip)
        self.btnOpen.setText(QCoreApplication.translate("MiniWireShark", u"...", None))
#if QT_CONFIG(tooltip)
        self.btnFlow.setToolTip(QCoreApplication.translate("MiniWireShark", u"\ud750\ub984\ub3c4 (Flow Graph)", None))
#endif // QT_CONFIG(tooltip)
        self.btnFlow.setText(QCoreApplication.translate("MiniWireShark", u"...", None))
#if QT_CONFIG(tooltip)
        self.btnRoute.setToolTip(QCoreApplication.translate("MiniWireShark", u"traceroute \uacbd\ub85c \uadf8\ub9bc", None))
#endif // QT_CONFIG(tooltip)
        self.btnRoute.setText(QCoreApplication.translate("MiniWireShark", u"...", None))
    # retranslateUi

