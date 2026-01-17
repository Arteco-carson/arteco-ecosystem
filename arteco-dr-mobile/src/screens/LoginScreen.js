import React, { useState, useContext } from 'react';
import { View, Text, TextInput, TouchableOpacity, StyleSheet, ActivityIndicator, Alert, SafeAreaView } from 'react-native';
import { AuthContext } from '../context/AuthContext';
import { login as loginService } from '../services/authservice';
import { User, Lock } from 'lucide-react-native';

const LoginScreen = ({ navigation }) => {
  const [username, setUsername] = useState('');
  const [password, setPassword] = useState('');
  const [loading, setLoading] = useState(false);
  const { login } = useContext(AuthContext);

  const handleLogin = async () => {
    if (!username || !password) {
      Alert.alert('Missing Fields', 'Please enter both username and password.');
      return;
    }

    setLoading(true);
    try {
      const data = await loginService(username.trim(), password);
      if (data.token) {
        login(data.token);
      } else {
        Alert.alert('Login Failed', 'Invalid response from server.');
      }
    } catch (error) {
      console.error(error);
      const errorMessage = error.message || 'Unknown error';
      if (!error.response) {
        Alert.alert('Connection Error', `Unable to connect to the server.\n\nDetails: ${errorMessage}`);
      } else if (error.response.status === 401) {
        Alert.alert('Login Failed', 'Invalid credentials.');
      } else {
        let serverMsg = 'No details provided by server';
        const data = error.response.data;
        if (data) {
          serverMsg = typeof data === 'object' ? (data.message || JSON.stringify(data)) : String(data);
        }
        const helpText = error.response.status === 500 ? '\n\n(Check Azure Log Stream for C# exceptions)' : '';
        Alert.alert('Login Failed', `Server error (${error.response.status}):\n${serverMsg}${helpText}`);
      }
    } finally {
      setLoading(false);
    }
  };

  return (
    <SafeAreaView style={styles.container}>
      <View style={styles.content}>
        <View style={styles.header}>
          <Text style={styles.title}>ARTECO</Text>
          <Text style={styles.subtitle}>Condition Reporting</Text>
        </View>

        <View style={styles.form}>
          <View style={styles.inputContainer}>
            <User color="#94a3b8" size={20} style={styles.icon} />
            <TextInput
              style={styles.input}
              placeholder="Username"
              value={username}
              onChangeText={setUsername}
              autoCapitalize="none"
              placeholderTextColor="#94a3b8"
            />
          </View>

          <View style={styles.inputContainer}>
            <Lock color="#94a3b8" size={20} style={styles.icon} />
            <TextInput
              style={styles.input}
              placeholder="Password"
              value={password}
              onChangeText={setPassword}
              secureTextEntry
              placeholderTextColor="#94a3b8"
            />
          </View>

          <TouchableOpacity 
            style={styles.button} 
            onPress={handleLogin}
            disabled={loading}
          >
            {loading ? (
              <ActivityIndicator color="white" />
            ) : (
              <Text style={styles.buttonText}>Sign In</Text>
            )}
          </TouchableOpacity>
          <View style={styles.linksContainer}>
            <TouchableOpacity onPress={() => navigation.navigate('ResetPassword')}>
              <Text style={styles.linkText}>Reset my password</Text>
            </TouchableOpacity>
            <TouchableOpacity onPress={() => navigation.navigate('Register')}>
              <Text style={styles.linkText}>Register a new user</Text>
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

export default LoginScreen;
