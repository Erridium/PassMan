import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import javax.swing.*;
import java.awt.*;
import java.awt.event.*;
import java.io.*;
import java.security.MessageDigest;
import java.util.Base64;
import java.util.HashMap;
import java.util.Map;

public class PasswordManagerGUI {
    private Map<String, Map<String, String>> passwordMap; // site -> (login -> password)
    private static final String FILE_NAME = "passwords.txt";
    private static final String MASTER_PASSWORD_FILE = "master_password.txt";
    private JFrame frame;
    private JTextArea textArea;
    private JTextField siteField;
    private JTextField loginField;
    private JTextField passwordField;
    private String masterPasswordHash;

    public PasswordManagerGUI() {
        passwordMap = new HashMap<>();
        loadMasterPasswordHash();
        createAndShowGUI();
        loadPasswords();
    }

    private void createAndShowGUI() {
        frame = new JFrame("Password Manager");
        frame.setDefaultCloseOperation(JFrame.EXIT_ON_CLOSE);
        frame.setSize(400, 300);
        frame.setLayout(new BorderLayout());

        textArea = new JTextArea();
        textArea.setEditable(false);
        JScrollPane scrollPane = new JScrollPane(textArea);
        frame.add(scrollPane, BorderLayout.CENTER);

        JPanel inputPanel = new JPanel();
        inputPanel.setLayout(new GridBagLayout());
        GridBagConstraints gbc = new GridBagConstraints();
        gbc.fill = GridBagConstraints.HORIZONTAL;
        gbc.insets = new Insets(5, 5, 5, 5); // Add some padding

        // Site Label and Field
        gbc.gridx = 0; // Column 0
        gbc.gridy = 0; // Row 0
        gbc.weightx = 1.0; // Horizontal scale
        gbc.fill = GridBagConstraints.HORIZONTAL; // Justify width
        inputPanel.add(new JLabel("Site:"), gbc);

        gbc.gridx = 1; // Column 1
        inputPanel.add(siteField = new JTextField(), gbc);

        // Login Label and Field
        gbc.gridx = 0; // Column 0
        gbc.gridy = 1; // Row 1
        gbc.weightx = 1.0; // Horizontal scale
        gbc.fill = GridBagConstraints.HORIZONTAL; // Justify width
        inputPanel.add(new JLabel("Login:"), gbc);

        gbc.gridx = 1; // Column 1
        inputPanel.add(loginField = new JTextField(), gbc);

        // Password Label and Field
        gbc.gridx = 0; // Column 0
        gbc.gridy = 2; // Row 2
        gbc.weightx = 1.0; // Horizontal scale
        gbc.fill = GridBagConstraints.HORIZONTAL; // Justify width
        inputPanel.add(new JLabel("Password:"), gbc);

        gbc.gridx = 1; // Column 1
        inputPanel.add(passwordField = new JTextField(), gbc);

 /*       // Buttons
        gbc.gridx = 0; // Column 0
        gbc.gridy = 3; // Row 3
        gbc.gridwidth = 2; // Span across both columns
        gbc.fill = GridBagConstraints.CENTER;
*/
        // Buttons
        gbc.gridx = 0; // Column 0
        gbc.gridy = 3; // Row 3
        gbc.gridwidth = 1; // Span across one column
        gbc.fill = GridBagConstraints.HORIZONTAL;

        JButton addButton = new JButton("Add");
        addButton.addActionListener(e -> addPassword());
        inputPanel.add(addButton, gbc);

        gbc.gridx = 1; // Column 1
        JButton changeButton = new JButton("Change");
        changeButton.addActionListener(e -> changePassword());
        inputPanel.add(changeButton, gbc);

        gbc.gridx = 0; // Column 0
        gbc.gridy = 4; // Move to the next row for the delete button
        gbc.gridwidth = 2; // Span across both columns
        JButton deleteButton = new JButton("Delete");
        deleteButton.addActionListener(e -> deletePassword());
        inputPanel.add(deleteButton, gbc);


        frame.add(inputPanel, BorderLayout.SOUTH);

        frame.addWindowListener(new WindowAdapter() {
            @Override
            public void windowClosing(WindowEvent e) {
                savePasswords();
                System.exit(0);
            }
        });

        frame.setVisible(true);
    }

    private void addPassword() {
        String site = siteField.getText();
        String login = loginField.getText();
        String password = passwordField.getText();
        if (!site.isEmpty() && !login.isEmpty() && !password.isEmpty()) {
            String encryptedPassword = encrypt(password);
            passwordMap.computeIfAbsent(site, k -> new HashMap<>()).put(login, encryptedPassword);
            updateTextArea();
            clearFields();
        } else {
            showMessage("Please enter site, login, and password.");
        }
    }

    private void changePassword() {
        String site = siteField.getText();
        String login = loginField.getText();
        String newPassword = passwordField.getText();
        if (passwordMap.containsKey(site) && passwordMap.get(site).containsKey(login)) {
            String encryptedPassword = encrypt(newPassword);
            passwordMap.get(site).put(login, encryptedPassword);
            updateTextArea();
            clearFields();
        } else {
            showMessage("No entry found for " + site + " with login " + login);
        }
    }

    private void deletePassword() {
        String site = siteField.getText();
        String login = loginField.getText();
        if (passwordMap.containsKey(site) && passwordMap.get(site).remove(login) != null) {
            if (passwordMap.get(site).isEmpty()) {
                passwordMap.remove(site); // Remove site if no logins left
            }
            updateTextArea();
            clearFields();
        } else {
            showMessage("No entry found for " + site + " with login " + login);
        }
    }

    private void updateTextArea() {
        textArea.setText("");
        for (Map.Entry<String, Map<String, String>> siteEntry : passwordMap.entrySet()) {
            String site = siteEntry.getKey();
            for (Map.Entry<String, String> loginEntry : siteEntry.getValue().entrySet()) {
                String decryptedPassword = decrypt(loginEntry.getValue());
                textArea.append("Site: " + site + ", Login: " + loginEntry.getKey() + ", Password: " + decryptedPassword + "\n");
            }
        }
    }

    private void clearFields() {
        siteField.setText("");
        loginField.setText("");
        passwordField.setText("");
    }

    private void showMessage(String message) {
        JOptionPane.showMessageDialog(frame, message);
    }

    private void loadMasterPasswordHash() {
        try (BufferedReader br = new BufferedReader(new FileReader(MASTER_PASSWORD_FILE))) {
            masterPasswordHash = br.readLine();
        } catch (IOException e) {
            // If the file doesn't exist, prompt for a master password
            promptForMasterPassword();
            return;
        }

        // Prompt for the master password and validate it
        boolean isValid = false;
        while (!isValid) {
            String masterPassword = JOptionPane.showInputDialog(frame, "Enter your master password:");
            if (masterPassword == null) {
                System.exit(0); // Exit if the user cancels
            }
            String enteredPasswordHash = hashPassword(masterPassword);
            if (enteredPasswordHash.equals(masterPasswordHash)) {
                isValid = true; // Password is correct
            } else {
                showMessage("Incorrect master password. Please try again.");
            }
        }
    }

    private void promptForMasterPassword() {
        String masterPassword = JOptionPane.showInputDialog(frame, "Enter a master password:");
        if (masterPassword != null) {
            masterPasswordHash = hashPassword(masterPassword);
            saveMasterPasswordHash();
        } else {
            System.exit(0); // Exit if the user cancels
        }
    }

    private void saveMasterPasswordHash() {
        try (BufferedWriter bw = new BufferedWriter(new FileWriter(MASTER_PASSWORD_FILE))) {
            bw.write(masterPasswordHash);
        } catch (IOException e) {
            System.out.println("Error saving master password hash: " + e.getMessage());
        }
    }

    private String hashPassword(String password) {
        try {
            MessageDigest digest = MessageDigest.getInstance("SHA-256");
            byte[] hash = digest.digest(password.getBytes("UTF-8"));
            return Base64.getEncoder().encodeToString(hash);
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
    }

    private SecretKey getSecretKey() {
        byte[] key = Base64.getDecoder().decode(masterPasswordHash);
        return new SecretKeySpec(key, 0, key.length, "AES");
    }

    private String encrypt(String password) {
        try {
            SecretKey secretKey = getSecretKey();
            Cipher cipher = Cipher.getInstance("AES");
            cipher.init(Cipher.ENCRYPT_MODE, secretKey);
            byte[] encrypted = cipher.doFinal(password.getBytes("UTF-8"));
            return Base64.getEncoder().encodeToString(encrypted);
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
    }

    private String decrypt(String encryptedPassword) {
        try {
            SecretKey secretKey = getSecretKey();
            Cipher cipher = Cipher.getInstance("AES");
            cipher.init(Cipher.DECRYPT_MODE, secretKey);
            byte[] decrypted = cipher.doFinal(Base64.getDecoder().decode(encryptedPassword));
            return new String(decrypted, "UTF-8");
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
    }

    private void loadPasswords() {
        try (BufferedReader br = new BufferedReader(new FileReader(FILE_NAME))) {
            String line;
            while ((line = br.readLine()) != null) {
                String[] parts = line.split(":", 3);
                if (parts.length == 3) {
                    String site = parts[0];
                    String login = parts[1];
                    String encryptedPassword = parts[2];
                    passwordMap.computeIfAbsent(site, k -> new HashMap<>()).put(login, encryptedPassword);
                }
            }
            updateTextArea(); // Update the text area after loading passwords
        } catch (IOException e) {
            System.out.println("Error loading passwords: " + e.getMessage());
        }
    }

    private void savePasswords() {
        try (BufferedWriter bw = new BufferedWriter(new FileWriter(FILE_NAME))) {
            for (Map.Entry<String, Map<String, String>> siteEntry : passwordMap.entrySet()) {
                String site = siteEntry.getKey();
                for (Map.Entry<String, String> loginEntry : siteEntry.getValue().entrySet()) {
                    bw.write(site + ":" + loginEntry.getKey() + ":" + loginEntry.getValue());
                    bw.newLine();
                }
            }
        } catch (IOException e) {
            System.out.println("Error saving passwords: " + e.getMessage());
        }
    }

    public static void main(String[] args) {
        SwingUtilities.invokeLater(PasswordManagerGUI::new);
    }
}

