const functions = require('firebase-functions');
const admin = require('firebase-admin');
admin.initializeApp();

// Instantly change a user's password
exports.setUserPassword = functions.https.onCall(async (data, context) => {
  if (!context.auth) throw new functions.https.HttpsError('unauthenticated', 'Not logged in.');
  const callerDoc = await admin.firestore().collection('users').doc(context.auth.uid).get();
  if (!callerDoc.exists) throw new functions.https.HttpsError('not-found', 'User not found.');
  const callerRole = callerDoc.data().role;
  if (callerRole !== 'owner' && callerRole !== 'admin') throw new functions.https.HttpsError('permission-denied', 'Not allowed.');
  const { uid, password } = data;
  if (!uid || !password || password.length < 6) throw new functions.https.HttpsError('invalid-argument', 'Invalid data.');
  await admin.auth().updateUser(uid, { password });
  await admin.firestore().collection('users').doc(uid).update({ password });
  return { success: true };
});

// Instantly change a user's username
exports.setUserUsername = functions.https.onCall(async (data, context) => {
  if (!context.auth) throw new functions.https.HttpsError('unauthenticated', 'Not logged in.');
  const callerDoc = await admin.firestore().collection('users').doc(context.auth.uid).get();
  if (!callerDoc.exists) throw new functions.https.HttpsError('not-found', 'User not found.');
  const callerRole = callerDoc.data().role;
  if (callerRole !== 'owner' && callerRole !== 'admin') throw new functions.https.HttpsError('permission-denied', 'Not allowed.');
  const { uid, username } = data;
  if (!uid || !username || !username.trim()) throw new functions.https.HttpsError('invalid-argument', 'Invalid data.');
  // Check username not already taken
  const existing = await admin.firestore().collection('users').where('username', '==', username.trim().toLowerCase()).get();
  if (!existing.empty && existing.docs[0].id !== uid) throw new functions.https.HttpsError('already-exists', 'Username taken.');
  await admin.firestore().collection('users').doc(uid).update({ username: username.trim().toLowerCase() });
  return { success: true };
});