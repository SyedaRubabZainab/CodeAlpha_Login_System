//  Purpose : Secure file-based user authentication system
//  Security: Passwords hashed with DJB2 (no plain-text storage)

#include <iostream>
#include <fstream>
#include <sstream>
#include <string>
#include <vector>
#include <algorithm>
#include <limits>
#include <ctime>
#include <iomanip>

using namespace std;

const string DB_FILE      = "users.db";
const int    MIN_PASS     = 6;
const int    MIN_USER     = 3;
const int    MAX_ATTEMPTS = 3;

// Simple DJB2 hash
string hashPassword(const string& password) {
    unsigned long hash = 5381;
    for (char c : password)
        hash = ((hash << 5) + hash) + (unsigned char)c;
    ostringstream oss;
    oss << hex << hash;
    return oss.str();
}

void printHeader() {
    cout << "\n";
    cout << "  +==========================================+\n";
    cout << "  |           LOGIN & REGISTRATION           |\n";
    cout << "  +==========================================+\n\n";
}

void printLine() {
    cout << "  ------------------------------------------\n";
}

string getInput(const string& prompt) {
    string val;
    cout << prompt;
    getline(cin, val);
    val.erase(0, val.find_first_not_of(" \t"));
    if (!val.empty())
        val.erase(val.find_last_not_of(" \t") + 1);
    return val;
}

string getPassword(const string& prompt) {
    cout << prompt;
    string pass;
    getline(cin, pass);
    return pass;
}

bool isValidUsername(const string& u) {
    if ((int)u.size() < MIN_USER) return false;
    for (char c : u)
        if (!isalnum(c) && c != '_' && c != '.') return false;
    return true;
}

bool isValidPassword(const string& p) {
    if ((int)p.size() < MIN_PASS) return false;
    bool hasUpper = false, hasDigit = false;
    for (char c : p) {
        if (isupper(c)) hasUpper = true;
        if (isdigit(c)) hasDigit = true;
    }
    return hasUpper && hasDigit;
}

struct UserRecord {
    string username;
    string passwordHash;
    string fullName;
    string createdAt;
};

vector<UserRecord> loadUsers() {
    vector<UserRecord> users;
    ifstream file(DB_FILE);
    if (!file.is_open()) return users;
    string line;
    while (getline(file, line)) {
        if (line.empty()) continue;
        istringstream ss(line);
        UserRecord u;
        getline(ss, u.username,     ':');
        getline(ss, u.passwordHash, ':');
        getline(ss, u.fullName,     ':');
        getline(ss, u.createdAt,    ':');
        users.push_back(u);
    }
    return users;
}

void saveUsers(const vector<UserRecord>& users) {
    ofstream file(DB_FILE);
    for (const auto& u : users)
        file << u.username << ":" << u.passwordHash << ":"
             << u.fullName << ":" << u.createdAt << "\n";
}

bool usernameExists(const vector<UserRecord>& users, const string& uname) {
    for (const auto& u : users)
        if (u.username == uname) return true;
    return false;
}

string currentTimestamp() {
    time_t now = time(nullptr);
    char buf[20];
    strftime(buf, sizeof(buf), "%Y-%m-%d %H:%M:%S", localtime(&now));
    return string(buf);
}

void registerUser() {
    cout << "\n";
    printLine();
    cout << "  REGISTER NEW ACCOUNT\n";
    printLine();

    vector<UserRecord> users = loadUsers();

    string fullName = getInput("  Full Name     : ");
    if (fullName.empty()) {
        cout << "  [!] Full name cannot be empty.\n";
        return;
    }

    string username;
    while (true) {
        username = getInput("  Username      : ");
        if (!isValidUsername(username)) {
            cout << "  [!] Username must be at least " << MIN_USER
                 << " chars (letters, digits, _ or . only).\n";
            continue;
        }
        if (usernameExists(users, username)) {
            cout << "  [!] Username already taken. Choose another.\n";
            continue;
        }
        break;
    }

    string password;
    while (true) {
        password = getPassword("  Password      : ");
        if (!isValidPassword(password)) {
            cout << "  [!] Password must be at least " << MIN_PASS
                 << " chars with 1 uppercase letter and 1 digit.\n";
            continue;
        }
        string confirm = getPassword("  Confirm Pass  : ");
        if (password != confirm) {
            cout << "  [!] Passwords do not match. Try again.\n";
            continue;
        }
        break;
    }

    UserRecord newUser;
    newUser.username     = username;
    newUser.passwordHash = hashPassword(password);
    newUser.fullName     = fullName;
    newUser.createdAt    = currentTimestamp();

    users.push_back(newUser);
    saveUsers(users);

    cout << "\n  [OK] Registration successful!\n";
    cout << "  Welcome, " << fullName << "! You may now log in.\n";
    printLine();
}

void loginUser() {
    cout << "\n";
    printLine();
    cout << "  LOGIN\n";
    printLine();

    vector<UserRecord> users = loadUsers();
    if (users.empty()) {
        cout << "  [!] No accounts found. Please register first.\n";
        return;
    }

    string username = getInput("  Username : ");
    int    attempts = 0;

    while (attempts < MAX_ATTEMPTS) {
        string password = getPassword("  Password : ");
        string hashed   = hashPassword(password);

        bool found = false;
        for (const auto& u : users) {
            if (u.username == username && u.passwordHash == hashed) {
                found = true;
                cout << "\n   +==========================================+\n";
                cout << "   |          [OK] LOGIN SUCCESSFUL             |\n";
                cout << "   +--------------------------------------------+\n";
                cout << "   |  Welcome back : " << left << setw(24) << u.fullName  << " |\n";
                cout << "   |  Username     : " << left << setw(24) << u.username  << " |\n";
                cout << "   |  Member since : " << left << setw(24) << u.createdAt << " |\n";
                cout << "   +==========================================+\n\n";
                break;
            }
        }

        if (found) return;

        attempts++;
        int remaining = MAX_ATTEMPTS - attempts;
        if (remaining > 0)
            cout << "  [!] Incorrect password. " << remaining << " attempt(s) remaining.\n";
        else
            cout << "  [!] Too many failed attempts. Account temporarily locked.\n";
    }
}

void listUsers() {
    vector<UserRecord> users = loadUsers();
    cout << "\n";
    printLine();
    cout << "  REGISTERED USERS (" << users.size() << " total)\n";
    printLine();
    if (users.empty()) {
        cout << "  No users registered yet.\n";
    } else {
        cout << left << setw(15) << "  Username"
             << setw(17) << "Full Name" << "Joined\n";
        printLine();
        for (const auto& u : users)
            cout << "  " << left << setw(15) << u.username
                 << setw(15) << u.fullName << u.createdAt << "\n";
    }
    printLine();
}

int main() {
    printHeader();
    int choice;

    while (true) {
        cout << "  [1] Register\n";
        cout << "  [2] Login\n";
        cout << "  [3] View All Users\n";
        cout << "  [0] Exit\n\n";
        cout << "  Choice : ";
        cin >> choice;
        cin.ignore(numeric_limits<streamsize>::max(), '\n');

        switch (choice) {
            case 1: registerUser(); break;
            case 2: loginUser();    break;
            case 3: listUsers();    break;
            case 0:
                cout << "\n  Goodbye!\n\n";
                return 0;
            default:
                cout << "  [!] Invalid option.\n";
        }
        cout << "\n";
    }
}
