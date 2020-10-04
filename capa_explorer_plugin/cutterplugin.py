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
from PySide2.QtGui import QKeySequence, QFont, QColor
from PySide2.QtWidgets import (QAction, QGroupBox, QHBoxLayout, QLabel, QCheckBox,
                               QLineEdit, QMessageBox, QPushButton, QShortcut, QFrame,
                               QTabWidget, QTextEdit, QVBoxLayout, QWidget, QTreeView,
                               QPlainTextEdit, QFileDialog, QTreeWidget, QTreeWidgetItem, QTableWidget, QAbstractItemView, QTableWidgetItem, QHeaderView)


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
        

        # Add load button
        self.btn_load_capa_results = QPushButton()
        self.btn_load_capa_results.setText("Load capa JSON")
        self.btn_load_capa_results.setStyleSheet("margin-bottom: 2px;margin-right:2px");
        self.btn_load_capa_results.clicked.connect(self.load_file)

        self.tabs.setCornerWidget(self.btn_load_capa_results)
    
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

    def log(self, msg):
        """log to cutter console

        @param msg: message to log
        """
        cutter.message(f"[CAPAExplorer]: {msg}")

    def load_file(self):

        # Disable load button during loading
        self.btn_load_capa_results.setEnabled(False)
      
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
            except Exception as e:
                util.log('Could not load json file.')
        else:
            util.log('No file selected.')

        self.btn_load_capa_results.setEnabled(True)

class CAPAExplorerPlugin(cutter.CutterPlugin):
    name = "Capa explorer"
    description = "Lets you import and explore capa results in Cutter."
    version = "1.0"
    author = "@9wayhandshake"

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
    return CAPAExplorerPlugin()
