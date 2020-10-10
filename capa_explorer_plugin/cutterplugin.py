# -*- coding: utf-8 -*-
import cutter
import json
import CutterBindings
import collections
from . import capa_constants, util
import sys, os

from .model import CapaExplorerDataModel
from .view import CapaExplorerQtreeView
from .proxy import CapaExplorerRangeProxyModel, CapaExplorerSearchProxyModel

from PySide2.QtCore import SIGNAL, QObject, Qt
from PySide2.QtGui import QFont
from PySide2.QtWidgets import (QAction, QGroupBox, QHBoxLayout, QLabel, QCheckBox, QToolButton,
                               QLineEdit, QMessageBox, QTabWidget, QVBoxLayout, QWidget, QTreeView, QMenu,
                               QFileDialog, QMessageBox, QTreeWidget, QTableWidget, QAbstractItemView, 
                               QTableWidgetItem, QHeaderView)


class MyDockWidget(cutter.CutterDockWidget):
    def __init__(self, parent, action):
        super(MyDockWidget, self).__init__(parent, action)
        self.setObjectName("Capa explorer")
        self.setWindowTitle("Capa explorer")
        
        self._config = CutterBindings.Configuration.instance()
        self.model_data = CapaExplorerDataModel()

        self.range_model_proxy = CapaExplorerRangeProxyModel()
        self.range_model_proxy.setSourceModel(self.model_data)
        self.search_model_proxy = CapaExplorerSearchProxyModel()
        self.search_model_proxy.setSourceModel(self.range_model_proxy)

        self.create_view_tabs()
        self.create_menu()
        self.create_tree_tab_ui()
        self.create_view_attack()

        self.connect_signals()
        self.setWidget(self.tabs)
        self.show()
        
    def create_view_tabs(self):

        # Create tabs container
        self.tabs = QTabWidget()

        # Create the tabs
        self.tab_attack = QWidget(self.tabs)
        self.tab_tree_w_model = QWidget(self.tabs)

        self.tabs.addTab(self.tab_tree_w_model, "Tree View")
        self.tabs.addTab(self.tab_attack, "MITRE")
 
    def create_menu(self):
        # Define menu actions
        # Text, tooltip, function, enabled before file load
        self.disabled_menu_items = []

        menu_actions = [
            ("Load JSON file", '', self.cma_load_file, True),
            (),
            ("Auto rename functions", 'Auto renames functions according to capa detections, can result in very long function names.', self.cma_analyze_and_rename, False),
            ("Create flags", 'Creates flagspaces and flags from capa detections.', self.cma_create_flags, False),
            (),
            ("About", '', self.cma_display_about, True),
        ]

        self.capa_menu = QMenu()
        self.capa_menu.setToolTipsVisible(True)

        # Create qactions
        for action in menu_actions:
            if not len(action):
                # Create separator on empty
                self.capa_menu.addSeparator()
                continue

            a = QAction(self)
            a.setText(action[0])
            a.setToolTip(action[1])
            a.triggered.connect(action[2])
            a.setEnabled(action[3])
            if not action[3]:
                self.disabled_menu_items.append(a)
            self.capa_menu.addAction(a)

            # Create menu button
            font = QFont()
            font.setBold(True)
            self.btn_menu = QToolButton()
            self.btn_menu.setText('...')
            self.btn_menu.setFont(font)
            self.btn_menu.setPopupMode(QToolButton.InstantPopup)
            self.btn_menu.setMenu(self.capa_menu)
            self.btn_menu.setStyleSheet('QToolButton::menu-indicator { image: none; }')
            self.tabs.setCornerWidget(self.btn_menu,corner=Qt.TopRightCorner) 

    def create_tree_tab_ui(self):
        self.capa_tree_view_layout = QVBoxLayout()
        self.capa_tree_view_layout.setAlignment(Qt.AlignTop)

        self.chk_fcn_scope = QCheckBox("Limit to Current function")
        #TODO: reset state on load file
        self.chk_fcn_scope.setChecked(False)
        self.chk_fcn_scope.stateChanged.connect(self.slot_checkbox_limit_by_changed)

        self.input_search = QLineEdit()     
        self.input_search.setStyleSheet("margin:0px; padding:0px;");
        self.input_search.setPlaceholderText("search...")
        self.input_search.textChanged.connect(self.slot_limit_results_to_search)

        self.filter_controls_container = QGroupBox()
        self.filter_controls_container.setObjectName("scope")
        self.filter_controls_container.setFlat(True)
        self.filter_controls_container.setStyleSheet("#scope{border:0px; padding:0px; margin:0px;subcontrol-origin: padding; subcontrol-position: left top;}");
        self.filter_controls_layout = QHBoxLayout(self.filter_controls_container)
        self.filter_controls_layout.setContentsMargins(0, 0, 0, 0);
        self.filter_controls_layout.addWidget(self.input_search)
        self.filter_controls_layout.addWidget(self.chk_fcn_scope)

        self.view_tree = CapaExplorerQtreeView(self.search_model_proxy)
        self.view_tree.setModel(self.search_model_proxy)

        # Make it look a little nicer when no results are loaded
        self.view_tree.header().setStretchLastSection(True)
        

        self.capa_tree_view_layout.addWidget(self.filter_controls_container)
        self.capa_tree_view_layout.addWidget(self.view_tree)
        self.tab_tree_w_model.setLayout(self.capa_tree_view_layout)

    def create_view_attack(self):
        table_headers = [
            "ATT&CK Tactic",
            "ATT&CK Technique ",
        ]
        table = QTableWidget()
        table.setColumnCount(len(table_headers))
        table.verticalHeader().setVisible(False)
        table.setSortingEnabled(False)
        table.setEditTriggers(QAbstractItemView.NoEditTriggers)
        table.setFocusPolicy(Qt.NoFocus)
        table.setSelectionMode(QAbstractItemView.NoSelection)
        table.setHorizontalHeaderLabels(table_headers)
        table.horizontalHeader().setDefaultAlignment(Qt.AlignLeft)
        table.horizontalHeader().setStretchLastSection(True)
        table.setShowGrid(False)
        table.horizontalHeader().setSectionResizeMode(0, QHeaderView.ResizeToContents)
        table.horizontalHeader().setSectionResizeMode(1, QHeaderView.Stretch)
        #table.setStyleSheet("QTableWidget::item { padding: 25px; }")

        attack_view_layout = QVBoxLayout()
        attack_view_layout.setAlignment(Qt.AlignTop)

        self.attack_table = table

        attack_view_layout.addWidget(self.attack_table)
        self.tab_attack.setLayout(attack_view_layout)

        return table

    def connect_signals(self):

        QObject.connect(cutter.core(), SIGNAL("functionRenamed(RVA, QString)"), self.model_data.refresh_function_names)
        QObject.connect(cutter.core(), SIGNAL("functionsChanged()"), self.model_data.refresh_function_names)
        QObject.connect(cutter.core(), SIGNAL("seekChanged(RVA)"), self.signal_shim_slot_checkbox_limit_by_changed)

    def render_new_table_header_item(self, text):
        """create new table header item with our style
        @param text: header text to display
        """
        item = QTableWidgetItem(text)
        item.setForeground(self._config.getColor("graph.true"))
        font = QFont()
        font.setBold(True)
        item.setFont(font)
        return item
     
    def fill_attack_table(self, rules):
        tactics = collections.defaultdict(set)
        for key, rule in rules.items():
            if not rule["meta"].get("att&ck"): 
                continue

            for attack in rule["meta"]["att&ck"]:
                tactic, _, rest = attack.partition("::")
            if "::" in rest:
                technique, _, rest = rest.partition("::")
                subtechnique, _, id = rest.rpartition(" ")
                tactics[tactic].add((technique, subtechnique, id))
            else:
                technique, _, id = rest.rpartition(" ")
                tactics[tactic].add((technique, id))
        
        column_one = []
        column_two = []

        for (tactic, techniques) in sorted(tactics.items()):
            column_one.append(tactic.upper())
            # add extra space when more than one technique
            column_one.extend(["" for i in range(len(techniques) - 1)])

            for spec in sorted(techniques):
                if len(spec) == 2:
                    technique, id = spec
                    column_two.append("%s %s" % (technique, id))
                elif len(spec) == 3:
                    technique, subtechnique, id = spec
                    column_two.append("%s::%s %s" % (technique, subtechnique, id))
                else:
                    raise RuntimeError("unexpected ATT&CK spec format")

        self.attack_table.setRowCount(max(len(column_one), len(column_two)))

        for (row, value) in enumerate(column_one):
            self.attack_table.setItem(row, 0, self.render_new_table_header_item(value))

        for (row, value) in enumerate(column_two):
            self.attack_table.setItem(row, 1, QTableWidgetItem(value))

    def enable_menu_items_after_load(self):
        # enables menu actions after file is loaded
        for action in self.disabled_menu_items:
            action.setEnabled(True)  
            
    def slot_limit_results_to_search(self, text):
        """limit tree view results to search matches
        reset view after filter to maintain level 1 expansion
        """
        self.search_model_proxy.set_query(text)
        self.view_tree.reset_ui(should_sort=False)    

    def signal_shim_slot_checkbox_limit_by_changed(self):
        if self.chk_fcn_scope.isChecked():
            self.slot_checkbox_limit_by_changed(Qt.Checked)

    def slot_checkbox_limit_by_changed(self, state):
        """slot activated if checkbox clicked
        if checked, configure function filter if screen location is located in function, otherwise clear filter
        @param state: checked state
        """
        invoke_reset = True

        if state == Qt.Checked:
            minbound,maxbound = util.get_function_boundries_at_current_location()

            if self.range_model_proxy.min_ea == minbound and self.range_model_proxy.max_ea == maxbound:
                # Seek only changed within current function, avoid resetting tree
                invoke_reset = False

            self.limit_results_to_function((minbound,maxbound))
        else:
            self.range_model_proxy.reset_address_range_filter()

        if invoke_reset:
            self.view_tree.reset_ui()

    def limit_results_to_function(self, f):
        """add filter to limit results to current function
        adds new address range filter to include function bounds, allowing basic blocks matched within a function
        to be included in the results
        @param f: (tuple (maxbound, minbound))
        """
        if f:
            self.range_model_proxy.add_address_range_filter(f[0], f[1])
        else:
            # if function not exists don't display any results (assume address never -1)
            self.range_model_proxy.add_address_range_filter(-1, -1)

    # --- Menu Actions

    def cma_analyze_and_rename(self):
        message_box = QMessageBox()

        message_box.setStyleSheet("QLabel{min-width: 370px;}");
        message_box.setStandardButtons(QMessageBox.Cancel | QMessageBox.Ok)
        message_box.setEscapeButton(QMessageBox.Cancel)
        message_box.setDefaultButton(QMessageBox.Ok)

        message_box.setWindowTitle('Warning')
        message_box.setText('Depending on the size of the binary and the'' amount of \n'
                            'capa matches this feature can take some time to \n'
                            'complete and might make the UI freeze temporarily.')
        message_box.setInformativeText('Are you sure you want to proceed ?')

        ret = message_box.exec_()

        # Ok = 1024
        if ret == 1024:
            self.model_data.auto_rename_functions()
    
    def cma_create_flags(self):
        self.model_data.create_flags()

    def cma_display_about(self):
        c = CAPAExplorerPlugin()

        info_text = (
            "{description}\n\n"
            "https://github.com/ninewayhandshake/capa-explorer\n\n"
            "Version: {version}\n"
            "Author: {author}\n"
            "License: Apache License 2.0\n"
        ).format(
            version = c.version,
            author = c.author,
            description = c.description,
            )

        text = CAPAExplorerPlugin().name
        message_box = QMessageBox()
        message_box.setStyleSheet("QLabel{min-width: 370px;}");
        
        message_box.setWindowTitle('About')
        message_box.setText(text)
        message_box.setInformativeText(info_text)
        message_box.setStandardButtons(QMessageBox.Close)

        for i in message_box.findChildren(QLabel):
            i.setFocusPolicy(Qt.NoFocus)

        message_box.exec_()

    def cma_load_file(self):
    
        filename = QFileDialog.getOpenFileName()
        path = filename[0]

        if len(path):
            try:
                data = util.load_capa_json(path)

                self.fill_attack_table(data['rules'])
                self.model_data.clear()
                self.model_data.render_capa_doc(data)
                        
                # Restore ability to scroll on last column
                self.view_tree.header().setStretchLastSection(False)
                
                self.view_tree.slot_resize_columns_to_content()
                self.enable_menu_items_after_load()
            except Exception as e:
                util.log('Could not load json file.')
        else:
            util.log('No file selected.')

class CAPAExplorerPlugin(cutter.CutterPlugin):
    name = "Capa explorer"
    description = "Lets you import and explore capa results in Cutter."
    version = "1.1"
    author = "@9wayhandshake"
    license = "Apache License 2.0"

    def setupPlugin(self):
        pass

    def setupInterface(self, main):
        action = QAction("capa explorer", main)
        action.setCheckable(True)
        widget = MyDockWidget(main, action)
        main.addPluginDockWidget(widget, action)

    def terminate(self):
        pass

def create_cutter_plugin():
    try:
        return CAPAExplorerPlugin()
    except Exception as e:
        cutter.message(str(e))
    

