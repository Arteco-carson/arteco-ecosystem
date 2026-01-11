import React, { useState, useContext } from 'react';
import {
    View,
    Text,
    TextInput,
    TouchableOpacity,
    StyleSheet,
    Alert,
    ActivityIndicator,
    SafeAreaView,
    KeyboardAvoidingView,
    Platform,
    Modal,
    ScrollView
} from 'react-native';
import axios from 'axios';
import { useNavigation } from '@react-navigation/native';
import { ChevronLeft, Save, User, Globe, Calendar, X } from 'lucide-react-native';
import { AuthContext } from '../context/AuthContext';
import { BASE_URL } from '../config/env';

const AddArtistModalScreen = ({ visible, onClose, onArtistCreated }) => {
    const navigation = useNavigation();
    const { userToken, logout } = useContext(AuthContext);
    const [loading, setLoading] = useState(false);

    const [firstName, setFirstName] = useState('');
    const [lastName, setLastName] = useState('');
    const [pseudonym, setPseudonym] = useState('');
    const [nationality, setNationality] = useState('');
    const [birthYear, setBirthYear] = useState('');
    const [deathYear, setDeathYear] = useState('');
    const [biography, setBiography] = useState('');

    const handleCreateArtist = async () => {
        setLoading(true);
        try {
            if (!userToken) {
                Alert.alert('Authentication token not found.');
                return;
            }
            const headers = { Authorization: `Bearer ${userToken.trim()}` };
            const payload = {
                firstName: firstName,
                lastName: lastName,
                pseudonym: pseudonym,
                nationality: nationality,
                birthYear: parseInt(birthYear),
                deathYear: parseInt(deathYear),
                biography: biography
            };

            const res = await axios.post(`${BASE_URL}/artists`, payload, { headers });
            const newArtist = res.data;

            Alert.alert('Success', `Artist "${newArtist.firstName} ${newArtist.lastName}" created.`);
            setFirstName('');
            setLastName('');
            setPseudonym('');
            setNationality('');
            setBirthYear('');
            setDeathYear('');
            setBiography('');

            if (onArtistCreated) {
                onArtistCreated(newArtist);
            }
            onClose();
            navigation.goBack();

        } catch (error) {
            console.error('Failed to create artist:', error);
            Alert.alert('Error', 'Failed to create new artist.');
        } finally {
            setLoading(false);
        }
    };

    return (
        <Modal
            visible={visible}
            animationType="slide"
            presentationStyle="pageSheet"
        >
            <SafeAreaView style={styles.container}>
                <KeyboardAvoidingView
                    behavior={Platform.OS === "ios" ? "padding" : "height"}
                    style={{ flex: 1 }}
                >
                    <View style={styles.header}>
                        <TouchableOpacity onPress={onClose} style={styles.backButton}>
                            <ChevronLeft size={24} color="#fff" />
                            <Text style={styles.backButtonText}>Cancel</Text>
                        </TouchableOpacity>
                        <Text style={styles.headerTitle}>Create New Artist</Text>
                        <View style={{ width: 60 }} />
                    </View>

                    <ScrollView contentContainerStyle={styles.formContainer}>
                        <Text style={styles.label}>First Name</Text>
                        <TextInput
                            style={styles.input}
                            value={firstName}
                            onChangeText={setFirstName}
                        />
                        <Text style={styles.label}>Last Name *</Text>
                        <TextInput
                            style={styles.input}
                            value={lastName}
                            onChangeText={setLastName}
                        />
                        <Text style={styles.label}>Pseudonym</Text>
                        <TextInput
                            style={styles.input}
                            value={pseudonym}
                            onChangeText={setPseudonym}
                        />
                        <Text style={styles.label}>Nationality</Text>
                        <TextInput
                            style={styles.input}
                            value={nationality}
                            onChangeText={setNationality}
                        />
                        <View style={styles.inlineInputs}>
                            <View style={{ flex: 1, marginRight: 10 }}>
                                <Text style={styles.label}>Birth Year</Text>
                                <View style={styles.inputContainer}>
                                    <Calendar size={20} color="#94a3b8" style={styles.inputIcon} />
                                    <TextInput
                                        style={styles.input}
                                        value={birthYear}
                                        onChangeText={setBirthYear}
                                        keyboardType="number-pad"
                                        placeholderTextColor="#cbd5e1"
                                    />
                                </View>
                            </View>
                            <View style={{ flex: 1 }}>
                                <Text style={styles.label}>Death Year</Text>
                                <View style={styles.inputContainer}>
                                    <Calendar size={20} color="#94a3b8" style={styles.inputIcon} />
                                    <TextInput
                                        style={styles.input}
                                        value={deathYear}
                                        onChangeText={setDeathYear}
                                        keyboardType="number-pad"
                                        placeholderTextColor="#cbd5e1"
                                    />
                                </View>
                            </View>
                        </View>
                        <Text style={styles.label}>Biography</Text>
                        <TextInput
                            style={[styles.input, styles.textArea]}
                            value={biography}
                            onChangeText={setBiography}
                            multiline={true}
                            numberOfLines={4}
                            textAlignVertical="top"
                        />
                        <TouchableOpacity
                            style={styles.createButton}
                            onPress={handleCreateArtist}
                            disabled={loading}
                        >
                            {loading ? (
                                <ActivityIndicator color="#fff" />
                            ) : (
                                <Text style={styles.createButtonText}>Create Artist</Text>
                            )}
                        </TouchableOpacity>
                    </ScrollView>
                </KeyboardAvoidingView>
            </SafeAreaView>
        </Modal>
    );
};

const styles = StyleSheet.create({
    container: { flex: 1, backgroundColor: '#f8fafc' },
    header: { padding: 16, flexDirection: 'row', alignItems: 'center', justifyContent: 'space-between', backgroundColor: '#246A73' },
    backButton: { flexDirection: 'row', alignItems: 'center' },
    backButtonText: { color: '#fff', fontSize: 16, marginLeft: 4 },
    headerTitle: { fontSize: 18, fontWeight: 'bold', color: '#fff' },
    formContainer: { flex: 1, padding: 20 },
    label: { fontSize: 14, fontWeight: '600', color: '#475569', marginBottom: 8, marginTop: 12 },
    input: { backgroundColor: '#fff', borderWidth: 1, borderColor: '#cbd5e1', borderRadius: 8, padding: 12, fontSize: 16, color: '#1e293b' },
    inlineInputs: { flexDirection: 'row', justifyContent: 'space-between' },
    inputContainer: { flexDirection: 'row', alignItems: 'center', backgroundColor: '#fff', borderWidth: 1, borderColor: '#cbd5e1', borderRadius: 8 },
    inputIcon: { marginLeft: 12 },
    textArea: { backgroundColor: '#fff', borderWidth: 1, borderColor: '#cbd5e1', borderRadius: 8, height: 100, textAlignVertical: 'top' },
    createButton: { backgroundColor: '#246A73', padding: 16, borderRadius: 8, flexDirection: 'row', justifyContent: 'center', alignItems: 'center', marginTop: 30 },
    createButtonText: { color: '#fff', fontSize: 16, fontWeight: 'bold' },
    modalContainer: { flex: 1, backgroundColor: '#f8fafc' },
    modalHeader: { padding: 16, flexDirection: 'row', justifyContent: 'space-between', alignItems: 'center', backgroundColor: '#fff', borderBottomWidth: 1, borderColor: '#e2e8f0' },
    modalTitle: { fontSize: 18, fontWeight: 'bold', color: '#1e293b' },
    modalItem: { padding: 16, backgroundColor: '#fff', borderBottomWidth: 1, borderColor: '#f1f5f9', flexDirection: 'row', justifyContent: 'space-between', alignItems: 'center' },
    modalItemText: { fontSize: 16, color: '#334155' }
});

export default AddArtistModalScreen;