// resource.h — DdsTrayAgent resource identifiers

#pragma once

#define IDI_TRAYICON            100
#define IDR_TRAYMENU            101

// Tray menu commands
#define IDM_ENROLL              1001
#define IDM_ADMIN_APPROVE       1002
#define IDM_ADMIN_SETUP         1003
#define IDM_STATUS              1004
#define IDM_EXIT                1005
#define IDM_REFRESH_VAULT       1006  // AD-13: "Refresh stored password"
#define IDM_ABOUT               1007  // "About DDS..." — shows installed MSI version

// Internal window messages
#define WM_TRAYICON             (WM_USER + 1)
