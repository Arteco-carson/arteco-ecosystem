import React, { useState, useEffect, useContext, useCallback } from 'react';
import {
  View,
  Text,
  StyleSheet,
  ScrollView,
  TouchableOpacity,
  ActivityIndicator,
  Alert,
  Modal,
  TextInput,
  Switch,
  SafeAreaView,
  KeyboardAvoidingView,
  Platform,
  FlatList
} from 'react-native';
import axios from 'axios';
import { useNavigation } from '@react-navigation/native';
import { User, MapPin, CreditCard, Phone, Mail, Shield, Plus, X, Trash2, Save, Check } from 'lucide-react-native';
import { AuthContext } from '../context/AuthContext';
import { BASE_URL } from '../config/env';

const ProfileScreen = () => {
  const navigation = useNavigation();
  const { userToken, logout } = useContext(AuthContext);
  
  // State
  const [loading, setLoading] = useState(true);
  const [user, setUser] = useState({});
  const [locations, setLocations] = useState([]);
  const [roles, setRoles] = useState([]);
  const [currencies, setCurrencies] = useState([]);

  // Modals
  const [editProfileVisible, setEditProfileVisible] = useState(false);
  const [addLocationVisible, setAddLocationVisible] = useState(false);
  const [editLocationVisible, setEditLocationVisible] = useState(false);
  const [selectedLocation, setSelectedLocation] = useState(null);

  // Form States
  const [profileForm, setProfileForm] = useState({});
  const [locationForm, setLocationForm] = useState({});
  const [submitting, setSubmitting] = useState(false);

  // Fetch Data
  const fetchProfile = useCallback(async () => {
    if (!userToken) return;
    setLoading(true);
    try {
      const headers = { Authorization: `Bearer ${userToken}` };
      
      const [profileRes, locRes, roleRes, currRes] = await Promise.all([
        axios.get(`${BASE_URL}/user/profile`, { headers }),
        axios.get(`${BASE_URL}/locations`, { headers }),
        axios.get(`${BASE_URL}/userroles`, { headers }),
        axios.get(`${BASE_URL}/user/currencies`, { headers })
      ]);

      setUser(profileRes.data);
      setLocations(locRes.data);
      setRoles(roleRes.data);
      setCurrencies(currRes.data);
    } catch (error) {
      console.error('Fetch Profile Error:', error);
      if (error.response?.status === 401) {
        logout();
      } else {
        Alert.alert('Error', 'Failed to load profile data.');
      }
    } finally {
      setLoading(false);
    }
  }, [userToken, logout]);

  useEffect(() => {
    fetchProfile();
  }, [fetchProfile]);

  // Handlers
  const handleEditProfile = () => {
    setProfileForm({
      firstName: user.firstName,
      lastName: user.lastName,
      emailAddress: user.emailAddress || user.EmailAddress || user.email,
      telephoneNumber: user.telephoneNumber,
      roleId: user.roleId,
      currencyCode: user.currencyCode
    });
    setEditProfileVisible(true);
  };

  const submitProfileUpdate = async () => {
    setSubmitting(true);
    try {
      await axios.put(`${BASE_URL}/user/profile`, profileForm, {
        headers: { Authorization: `Bearer ${userToken}` }
      });
      Alert.alert('Success', 'Profile updated.');
      setEditProfileVisible(false);
      fetchProfile();
    } catch (error) {
      Alert.alert('Error', 'Failed to update profile.');
    } finally {
      setSubmitting(false);
    }
  };

  const handleAddLocation = () => {
    setLocationForm({
      locationName: '',
      addressLine1: '',
      city: '',
      postcode: '',
      country: '',
      isDefault: false
    });
    setAddLocationVisible(true);
  };

  const submitAddLocation = async () => {
    if (!locationForm.locationName) {
      Alert.alert('Validation', 'Location Name is required.');
      return;
    }
    setSubmitting(true);
    try {
      await axios.post(`${BASE_URL}/locations`, locationForm, {
        headers: { Authorization: `Bearer ${userToken}` }
      });
      Alert.alert('Success', 'Location added.');
      setAddLocationVisible(false);
      fetchProfile();
    } catch (error) {
      Alert.alert('Error', 'Failed to add location.');
    } finally {
      setSubmitting(false);
    }
  };

  const handleEditLocation = (loc) => {
    setSelectedLocation(loc);
    setLocationForm({
      locationName: loc.locationName,
      addressLine1: loc.addressLine1,
      city: loc.city,
      postcode: loc.postcode,
      country: loc.country,
      isDefault: loc.isDefault
    });
    setEditLocationVisible(true);
  };

  const submitUpdateLocation = async () => {
    setSubmitting(true);
    try {
      await axios.put(`${BASE_URL}/locations/${selectedLocation.locationId}`, { ...selectedLocation, ...locationForm }, {
        headers: { Authorization: `Bearer ${userToken}` }
      });
      Alert.alert('Success', 'Location updated.');
      setEditLocationVisible(false);
      fetchProfile();
    } catch (error) {
      Alert.alert('Error', 'Failed to update location.');
    } finally {
      setSubmitting(false);
    }
  };

  const handleDeleteLocation = () => {
    Alert.alert('Delete Location', 'Are you sure?', [
      { text: 'Cancel', style: 'cancel' },
      {
        text: 'Delete',
        style: 'destructive',
        onPress: async () => {
          try {
            await axios.delete(`${BASE_URL}/locations/${selectedLocation.locationId}`, {
              headers: { Authorization: `Bearer ${userToken}` }
            });
            setEditLocationVisible(false);
            fetchProfile();
          } catch (error) {
            Alert.alert('Error', 'Failed to delete location.');
          }
        }
      }
    ]);
  };

  // Render Helpers
  const renderLabelValue = (icon, label, value) => (
    <View style={styles.infoRow}>
      <View style={styles.infoLabelContainer}>
        {icon}
        <Text style={styles.infoLabel}>{label}</Text>
      </View>
      <Text style={styles.infoValue}>{value || 'N/A'}</Text>
    </View>
  );

  const renderInput = (label, value, onChange, placeholder, keyboardType = 'default') => (
    <View style={styles.inputContainer}>
      <Text style={styles.inputLabel}>{label}</Text>
      <TextInput
        style={styles.input}
        value={value}
        onChangeText={onChange}
        placeholder={placeholder}
        keyboardType={keyboardType}
        placeholderTextColor="#94a3b8"
      />
    </View>
  );

  if (loading) {
    return (
      <View style={styles.center}>
        <ActivityIndicator size="large" color="#246A73" />
      </View>
    );
  }

  return (
    <SafeAreaView style={styles.container}>
      <View style={styles.header}>
        <Text style={styles.headerTitle}>User Profile</Text>
        {user.userRole === 'Administrator' && (
           <TouchableOpacity onPress={() => Alert.alert('Info', 'System Logs are available on the web portal.')}>
             <Shield size={24} color="#fff" />
           </TouchableOpacity>
        )}
      </View>

      <ScrollView contentContainerStyle={styles.content}>
        {/* Identity Card */}
        <View style={styles.card}>
          <Text style={styles.cardTitle}>Identity Details</Text>
          {renderLabelValue(<User size={16} color="#64748b" />, "Full Name", `${user.firstName} ${user.lastName}`)}
          {renderLabelValue(<Mail size={16} color="#64748b" />, "Email", user.emailAddress || user.EmailAddress || user.email)}
          {renderLabelValue(<Phone size={16} color="#64748b" />, "Contact", user.telephoneNumber)}
          {renderLabelValue(<MapPin size={16} color="#64748b" />, "Country", locations.find(l => l.isDefault)?.country || user.location)}
          {renderLabelValue(<Shield size={16} color="#64748b" />, "Role", user.userRole)}
          {renderLabelValue(<CreditCard size={16} color="#64748b" />, "Currency", user.currencyCode)}
          
          <TouchableOpacity style={styles.editButton} onPress={handleEditProfile}>
            <Text style={styles.editButtonText}>Edit Profile</Text>
          </TouchableOpacity>
        </View>

        {/* Locations Card */}
        <View style={styles.card}>
          <View style={styles.cardHeaderRow}>
            <Text style={styles.cardTitle}>Assigned Locations</Text>
            <TouchableOpacity onPress={handleAddLocation}>
              <Plus size={20} color="#246A73" />
            </TouchableOpacity>
          </View>
          
          {locations.length === 0 ? (
            <Text style={styles.emptyText}>No locations assigned.</Text>
          ) : (
            locations.map(loc => (
              <TouchableOpacity 
                key={loc.locationId} 
                style={styles.locationItem}
                onPress={() => handleEditLocation(loc)}
              >
                <View>
                  <Text style={styles.locationName}>{loc.locationName}</Text>
                  <Text style={styles.locationDetail}>{loc.city}, {loc.country}</Text>
                </View>
                {loc.isDefault && <View style={styles.defaultBadge}><Text style={styles.defaultText}>Default</Text></View>}
              </TouchableOpacity>
            ))
          )}
        </View>
      </ScrollView>

      {/* Edit Profile Modal */}
      <Modal visible={editProfileVisible} animationType="slide" presentationStyle="pageSheet">
        <SafeAreaView style={styles.modalContainer}>
          <View style={styles.modalHeader}>
            <Text style={styles.modalTitle}>Edit Profile</Text>
            <TouchableOpacity onPress={() => setEditProfileVisible(false)}><X size={24} color="#1e293b" /></TouchableOpacity>
          </View>
          <ScrollView contentContainerStyle={styles.modalContent}>
            {renderInput("First Name", profileForm.firstName, (t) => setProfileForm({...profileForm, firstName: t}))}
            {renderInput("Last Name", profileForm.lastName, (t) => setProfileForm({...profileForm, lastName: t}))}
            {renderInput("Email", profileForm.emailAddress, (t) => setProfileForm({...profileForm, emailAddress: t}), "email@example.com", "email-address")}
            {renderInput("Phone", profileForm.telephoneNumber, (t) => setProfileForm({...profileForm, telephoneNumber: t}), "+44...", "phone-pad")}
            
            <Text style={styles.inputLabel}>Currency</Text>
            <View style={styles.pickerContainer}>
              <ScrollView horizontal showsHorizontalScrollIndicator={false}>
                {currencies.map(curr => (
                  <TouchableOpacity 
                    key={curr.currencyCode} 
                    style={[styles.chip, profileForm.currencyCode === curr.currencyCode && styles.chipSelected]}
                    onPress={() => setProfileForm({...profileForm, currencyCode: curr.currencyCode})}
                  >
                    <Text style={[styles.chipText, profileForm.currencyCode === curr.currencyCode && styles.chipTextSelected]}>{curr.currencyCode}</Text>
                  </TouchableOpacity>
                ))}
              </ScrollView>
            </View>

            <TouchableOpacity style={styles.saveButton} onPress={submitProfileUpdate} disabled={submitting}>
              {submitting ? <ActivityIndicator color="#fff" /> : <Text style={styles.saveButtonText}>Save Changes</Text>}
            </TouchableOpacity>
          </ScrollView>
        </SafeAreaView>
      </Modal>

      {/* Add/Edit Location Modal (Reused Logic) */}
      <Modal visible={addLocationVisible || editLocationVisible} animationType="slide" presentationStyle="pageSheet">
        <SafeAreaView style={styles.modalContainer}>
          <View style={styles.modalHeader}>
            <Text style={styles.modalTitle}>{addLocationVisible ? "Add Location" : "Edit Location"}</Text>
            <TouchableOpacity onPress={() => { setAddLocationVisible(false); setEditLocationVisible(false); }}>
              <X size={24} color="#1e293b" />
            </TouchableOpacity>
          </View>
          <ScrollView contentContainerStyle={styles.modalContent}>
            {renderInput("Location Name", locationForm.locationName, (t) => setLocationForm({...locationForm, locationName: t}))}
            {renderInput("Address", locationForm.addressLine1, (t) => setLocationForm({...locationForm, addressLine1: t}))}
            {renderInput("City", locationForm.city, (t) => setLocationForm({...locationForm, city: t}))}
            {renderInput("Postcode", locationForm.postcode, (t) => setLocationForm({...locationForm, postcode: t}))}
            {renderInput("Country", locationForm.country, (t) => setLocationForm({...locationForm, country: t}))}
            
            <View style={styles.switchRow}>
              <Text style={styles.inputLabel}>Set as Default</Text>
              <Switch 
                value={locationForm.isDefault} 
                onValueChange={(v) => setLocationForm({...locationForm, isDefault: v})}
                trackColor={{ false: "#cbd5e1", true: "#246A73" }}
              />
            </View>

            <TouchableOpacity 
              style={styles.saveButton} 
              onPress={addLocationVisible ? submitAddLocation : submitUpdateLocation} 
              disabled={submitting}
            >
              {submitting ? <ActivityIndicator color="#fff" /> : <Text style={styles.saveButtonText}>{addLocationVisible ? "Add Location" : "Update Location"}</Text>}
            </TouchableOpacity>

            {editLocationVisible && (
              <TouchableOpacity style={styles.deleteButton} onPress={handleDeleteLocation}>
                <Trash2 size={18} color="#ef4444" style={{ marginRight: 8 }} />
                <Text style={styles.deleteButtonText}>Delete Location</Text>
              </TouchableOpacity>
            )}
          </ScrollView>
        </SafeAreaView>
      </Modal>
      
    </SafeAreaView>
  );
};

const styles = StyleSheet.create({
  container: { flex: 1, backgroundColor: '#f8fafc' },
  center: { flex: 1, justifyContent: 'center', alignItems: 'center' },
  header: { padding: 16, flexDirection: 'row', alignItems: 'center', justifyContent: 'space-between', backgroundColor: '#246A73' },
  headerTitle: { fontSize: 20, fontWeight: 'bold', color: '#fff' },
  content: { padding: 16 },
  card: { backgroundColor: '#fff', borderRadius: 12, padding: 16, marginBottom: 16, borderWidth: 1, borderColor: '#e2e8f0' },
  cardTitle: { fontSize: 18, fontWeight: 'bold', color: '#1e293b', marginBottom: 16 },
  cardHeaderRow: { flexDirection: 'row', justifyContent: 'space-between', alignItems: 'center', marginBottom: 16 },
  infoRow: { flexDirection: 'row', justifyContent: 'space-between', alignItems: 'center', marginBottom: 12 },
  infoLabelContainer: { flexDirection: 'row', alignItems: 'center', gap: 8 },
  infoLabel: { color: '#64748b', fontSize: 14 },
  infoValue: { color: '#1e293b', fontSize: 14, fontWeight: '500' },
  editButton: { marginTop: 10, padding: 12, backgroundColor: '#f1f5f9', borderRadius: 8, alignItems: 'center' },
  editButtonText: { color: '#246A73', fontWeight: '600' },
  locationItem: { flexDirection: 'row', justifyContent: 'space-between', alignItems: 'center', paddingVertical: 12, borderBottomWidth: 1, borderBottomColor: '#f1f5f9' },
  locationName: { fontSize: 16, fontWeight: '600', color: '#1e293b' },
  locationDetail: { fontSize: 12, color: '#64748b' },
  defaultBadge: { backgroundColor: '#dcfce7', paddingHorizontal: 8, paddingVertical: 2, borderRadius: 4 },
  defaultText: { color: '#166534', fontSize: 10, fontWeight: 'bold' },
  emptyText: { color: '#94a3b8', fontStyle: 'italic' },
  
  // Modal Styles
  modalContainer: { flex: 1, backgroundColor: '#f8fafc' },
  modalHeader: { padding: 16, flexDirection: 'row', justifyContent: 'space-between', alignItems: 'center', backgroundColor: '#fff', borderBottomWidth: 1, borderColor: '#e2e8f0' },
  modalTitle: { fontSize: 18, fontWeight: 'bold', color: '#1e293b' },
  modalContent: { padding: 20 },
  inputContainer: { marginBottom: 16 },
  inputLabel: { fontSize: 14, fontWeight: '600', color: '#475569', marginBottom: 6 },
  input: { backgroundColor: '#fff', borderWidth: 1, borderColor: '#cbd5e1', borderRadius: 8, padding: 12, fontSize: 16, color: '#1e293b' },
  saveButton: { backgroundColor: '#246A73', padding: 16, borderRadius: 8, alignItems: 'center', marginTop: 20 },
  saveButtonText: { color: '#fff', fontSize: 16, fontWeight: 'bold' },
  deleteButton: { flexDirection: 'row', justifyContent: 'center', alignItems: 'center', marginTop: 16, padding: 16 },
  deleteButtonText: { color: '#ef4444', fontSize: 16, fontWeight: '600' },
  switchRow: { flexDirection: 'row', justifyContent: 'space-between', alignItems: 'center', marginVertical: 10 },
  pickerContainer: { flexDirection: 'row', marginBottom: 16 },
  chip: { paddingHorizontal: 16, paddingVertical: 8, borderRadius: 20, backgroundColor: '#f1f5f9', marginRight: 10, borderWidth: 1, borderColor: '#e2e8f0' },
  chipSelected: { backgroundColor: '#246A73', borderColor: '#246A73' },
  chipText: { color: '#64748b', fontWeight: '600' },
  chipTextSelected: { color: 'white' },
});

export default ProfileScreen;