/* tabnav_tree_widget.h
 * Tree widget with saner tab navigation properties.
 *
 * Copyright 2017 Peter Wu <peter@lekensteyn.nl>
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#ifndef TABNAV_TREE_WIDGET_H
#define TABNAV_TREE_WIDGET_H

#include <config.h>
#include <QTreeWidget>

/**
 * Like QTreeWidget, but instead of changing to the next row (same column) when
 * pressing Tab while editing, change to the next column (same row).
 */
class TabnavTreeWidget : public QTreeWidget
{
public:
    TabnavTreeWidget(QWidget *parent = 0);
    QModelIndex moveCursor(CursorAction cursorAction, Qt::KeyboardModifiers modifiers);
};
#endif // TABNAV_TREE_WIDGET_H
