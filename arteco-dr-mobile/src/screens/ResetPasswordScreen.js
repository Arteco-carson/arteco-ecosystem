import React, { useState } from 'react';
import { 
  View, 
  Text, 
  TextInput, 
  TouchableOpacity, 
  StyleSheet, 
  ActivityIndicator, 
  Alert, 
  SafeAreaView
} from 'react-native';
import { resetPassword as resetPasswordService } from '../services/authservice';
import { User, Lock } from 'lucide-react-native';

const ResetPasswordScreen = ({ navigation }) => {
  const [formData, setFormData] = useState({
    username: '',
    oldPassword: '',
    newPassword: '',
    confirmPassword: '',
  });
  const [loading, setLoading] = useState(false);

  const handleChange = (name, value) => {
    setFormData(prev => ({ ...prev, [name]: value }));
  };

  const handleResetPassword = async () => {
    const { username, oldPassword, newPassword, confirmPassword } = formData;
    if (!username || !oldPassword || !newPassword || !confirmPassword) {
      Alert.alert('Missing Fields', 'Please fill in all fields.');
      return;
    }
    if (newPassword !== confirmPassword) {
      Alert.alert('Password Mismatch', 'New passwords do not match.');
      return;
    }

    setLoading(true);
    try {
      await resetPasswordService(formData);
      Alert.alert('Success', 'Your password has been reset successfully.', [
        { text: 'OK', onPress: () => navigation.goBack() }
      ]);
    } catch (error) {
      console.error(error);
      const errorMessage = error.response?.data?.message || 'Could not reset password. Please try again.';
      Alert.alert('Reset Failed', errorMessage);
    } finally {
      setLoading(false);
    }
  };

  return (
    <SafeAreaView style={styles.container}>
      <View style={styles.content}>
        <View style={styles.header}>
          <Text style={styles.title}>ARTECO</Text>
          <Text style={styles.subtitle}>Reset Password</Text>
        </View>

        <View style={styles.form}>
            <View style={styles.inputContainer}>
                <User color="#94a3b8" size={20} style={styles.icon} />
                <TextInput
                style={styles.input}
                placeholder="Username"
                value={formData.username}
                onChangeText={(text) => handleChange('username', text)}
                autoCapitalize="none"
                placeholderTextColor="#94a3b8"
                />
            </View>

            <View style={styles.inputContainer}>
                <Lock color="#94a3b8" size={20} style={styles.icon} />
                <TextInput
                style={styles.input}
                placeholder="Old Password"
                value={formData.oldPassword}
                onChangeText={(text) => handleChange('oldPassword', text)}
                secureTextEntry
                placeholderTextColor="#94a3b8"
                />
            </View>

            <View style={styles.inputContainer}>
                <Lock color="#94a3b8" size={20} style={styles.icon} />
                <TextInput
                style={styles.input}
                placeholder="New Password"
                value={formData.newPassword}
                onChangeText={(text) => handleChange('newPassword', text)}
                secureTextEntry
                placeholderTextColor="#94a3b8"
                />
            </View>

            <View style={styles.inputContainer}>
                <Lock color="#94a3b8" size={20} style={styles.icon} />
                <TextInput
                style={styles.input}
                placeholder="Confirm New Password"
                value={formData.confirmPassword}
                onChangeText={(text) => handleChange('confirmPassword', text)}
                secureTextEntry
                placeholderTextColor="#94a3b8"
                />
            </View>

          <TouchableOpacity 
            style={styles.button} 
            onPress={handleResetPassword}
            disabled={loading}
          >
            {loading ? (
              <ActivityIndicator color="white" />
            ) : (
              <Text style={styles.buttonText}>Reset Password</Text>
            )}
          </TouchableOpacity>
          
          <View style={styles.linksContainer}>
             <TouchableOpacity onPress={() => navigation.goBack()}>
                <Text style={styles.linkText}>Back to Login</Text>
            </TouchableOpacity>
          </View>
        </View>
      </View>
    </SafeAreaView>
  );
};

const styles = StyleSheet.create({
  container: { flex: 1, backgroundColor: '#f0f2f5' },
  content: { flex: 1, justifyContent: 'center', padding: 20 },
  header: { alignItems: 'center', marginBottom: 40 },
  title: { fontSize: 32, fontWeight: 'bold', color: '#246A73' },
  subtitle: { fontSize: 16, color: '#64748b', marginTop: 5 },
  form: { backgroundColor: 'white', padding: 20, borderRadius: 12, shadowColor: '#000', shadowOpacity: 0.1, shadowRadius: 10, elevation: 5 },
  inputContainer: { flexDirection: 'row', alignItems: 'center', borderWidth: 1, borderColor: '#cbd5e1', borderRadius: 8, marginBottom: 15, paddingHorizontal: 10, height: 50 },
  icon: { marginRight: 10 },
  input: { flex: 1, color: '#1e293b' },
  button: { backgroundColor: '#246A73', height: 50, borderRadius: 8, justifyContent: 'center', alignItems: 'center', marginTop: 10 },
  buttonText: { color: 'white', fontWeight: 'bold', fontSize: 16 },
  linksContainer: {
    marginTop: 20,
    alignItems: 'center',
  },
  linkText: {
    color: '#246A73',
    fontSize: 14,
    marginBottom: 10,
  },
});

export default ResetPasswordScreen;
