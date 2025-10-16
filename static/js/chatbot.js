// Disease database with symptoms and precautions
const diseaseDatabase = {
    'fever': {
        name: 'Fever',
        symptoms: ['High body temperature', 'Chills', 'Sweating', 'Headache', 'Muscle aches', 'Weakness'],
        precautions: [
            'Drink plenty of fluids to stay hydrated',
            'Get adequate rest',
            'Take fever-reducing medication as directed',
            'Use cool compresses to reduce temperature',
            'Seek medical attention if fever persists beyond 3 days'
        ]
    },
    'migraine': {
        name: 'Migraine Headache',
        symptoms: ['Severe headache', 'Nausea', 'Sensitivity to light/sound', 'Aura', 'Throbbing pain'],
        precautions: [
            'Rest in a quiet, dark room',
            'Apply cold compresses to head',
            'Take prescribed migraine medication',
            'Stay hydrated',
            'Identify and avoid trigger factors'
        ]
    },
    'hypertension': {
        name: 'High Blood Pressure',
        symptoms: ['Headaches', 'Shortness of breath', 'Nosebleeds', 'Dizziness', 'Chest pain'],
        precautions: [
            'Reduce sodium intake',
            'Exercise regularly',
            'Maintain healthy weight',
            'Limit alcohol and caffeine',
            'Take prescribed medications as directed'
        ]
    },
    'diabetes': {
        name: 'Diabetes',
        symptoms: ['Increased thirst', 'Frequent urination', 'Fatigue', 'Blurred vision', 'Slow healing'],
        precautions: [
            'Monitor blood sugar levels regularly',
            'Follow a balanced diet',
            'Exercise regularly',
            'Take medications as prescribed',
            'Get regular eye and foot checkups'
        ]
    },
    'asthma': {
        name: 'Asthma',
        symptoms: ['Wheezing', 'Shortness of breath', 'Chest tightness', 'Coughing', 'Difficulty breathing'],
        precautions: [
            'Avoid known allergens',
            'Keep rescue inhaler handy',
            'Avoid smoke and pollution',
            'Get vaccinated for flu/pneumonia',
            'Follow asthma action plan'
        ]
    },
    'arthritis': {
        name: 'Arthritis',
        symptoms: ['Joint pain', 'Stiffness', 'Swelling', 'Decreased range of motion', 'Redness'],
        precautions: [
            'Maintain healthy weight',
            'Exercise regularly',
            'Apply hot/cold compresses',
            'Use assistive devices if needed',
            'Take prescribed medications'
        ]
    },
    'anemia': {
        name: 'Anemia',
        symptoms: ['Fatigue', 'Weakness', 'Pale skin', 'Shortness of breath', 'Dizziness'],
        precautions: [
            'Eat iron-rich foods',
            'Take iron supplements if prescribed',
            'Include vitamin C to enhance iron absorption',
            'Avoid tea/coffee with meals',
            'Get regular blood tests'
        ]
    },
    'gastritis': {
        name: 'Gastritis',
        symptoms: ['Stomach pain', 'Nausea', 'Vomiting', 'Bloating', 'Loss of appetite'],
        precautions: [
            'Avoid spicy and acidic foods',
            'Eat smaller, frequent meals',
            'Limit alcohol and caffeine',
            'Avoid NSAIDs if possible',
            'Manage stress levels'
        ]
    },
    'urinary tract infection': {
        name: 'Urinary Tract Infection (UTI)',
        symptoms: ['Burning sensation', 'Frequent urination', 'Cloudy urine', 'Pelvic pain', 'Strong-smelling urine'],
        precautions: [
            'Drink plenty of water',
            'Urinate after intercourse',
            'Wipe from front to back',
            'Avoid irritating feminine products',
            'Complete full course of antibiotics'
        ]
    },
    'allergic rhinitis': {
        name: 'Allergic Rhinitis (Hay Fever)',
        symptoms: ['Sneezing', 'Runny nose', 'Itchy eyes', 'Nasal congestion', 'Postnasal drip'],
        precautions: [
            'Avoid known allergens',
            'Use air purifiers',
            'Keep windows closed during high pollen',
            'Shower after being outdoors',
            'Use saline nasal sprays'
        ]
        ]
    }
};

// Common symptoms mapping to diseases
const symptomToDisease = {
    'fever': 'fever',
    'temperature': 'fever',
    'cold': 'common cold',
    'sneezing': 'common cold',
    'runny nose': 'common cold',
    'chest pain': 'heart disease',
    'chest discomfort': 'heart disease',
    'shortness of breath': 'heart disease',
    'cough with phlegm': 'pneumonia',
    'persistent cough': 'lung cancer',
    'blood in sputum': 'lung cancer',
    'weight loss': 'lung cancer',
    'headache': 'brain tumor',
    'dizziness': 'brain tumor',
    'vision problems': 'brain tumor',
    'frequent urination': 'diabetes',
    'thirst': 'diabetes',
    'fatigue': 'diabetes',
    'high blood pressure': 'hypertension',
    'nosebleeds': 'hypertension',
    'wheezing': 'asthma',
    'cough at night': 'asthma',
    'diarrhea': 'gastroenteritis',
    'vomiting': 'gastroenteritis',
    'stomach cramps': 'gastroenteritis'
};

// Chatbot state
let chatState = 'initial';
let selectedDisease = null;

// DOM Elements
const chatButton = document.getElementById('chatbot-button');
const chatWindow = document.getElementById('chatbot-window');
const chatMessages = document.getElementById('chat-messages');
const chatInput = document.getElementById('chat-input');
const sendButton = document.getElementById('send-button');
const closeButton = document.getElementById('chatbot-close');

// Initialize the chatbot
function initChatbot() {
    // Toggle chat window
    chatButton.addEventListener('click', toggleChatWindow);
    closeButton.addEventListener('click', toggleChatWindow);
    
    // Send message when clicking send button or pressing Enter
    sendButton.addEventListener('click', handleUserMessage);
    chatInput.addEventListener('keypress', (e) => {
        if (e.key === 'Enter') {
            handleUserMessage();
        }
    });
    
    // Show welcome message
    setTimeout(showWelcomeMessage, 1000);
}

// Toggle chat window visibility
function toggleChatWindow() {
    chatWindow.style.display = chatWindow.style.display === 'flex' ? 'none' : 'flex';
    if (chatWindow.style.display === 'flex') {
    }
}

// Show welcome message
function showWelcomeMessage() {
    const welcomeMessage = `👋 Hello there! I'm your friendly Health Assistant, here to help you with health-related information. I can provide guidance on common medical conditions, symptoms, and general health advice.

💡 Here's what I can help you with:
• Information about common health conditions
• Symptoms and warning signs to watch for
• Basic first aid and self-care tips
• General health and wellness advice
• When to seek medical attention

Feel free to ask me anything, or choose from the quick options below!`;
    
    const quickReplies = [
        '🤒 Fever management',
        '🤧 Cold & Allergies',
        '❤️ Heart health',
        '🩸 Diabetes care',
        '🌬️ Asthma help',
        '🤕 Headache relief'
    ];
    
    addBotMessage(welcomeMessage, createQuickReplies(quickReplies));
    
    // Add a small delay before showing a follow-up message
    setTimeout(() => {
        addBotMessage("You can ask me things like:\n• 'What are the symptoms of flu?'\n• 'How to lower blood pressure naturally?'\n• 'First aid for burns'\n• 'When to see a doctor for a fever?'");
    }, 1500);
}

// Create a set of quick reply buttons
function createQuickReplies(options) {
    const quickReplies = document.createElement('div');
    quickReplies.className = 'quick-replies';
    
    options.forEach(option => {
        const button = document.createElement('div');
        button.className = 'quick-reply';
        button.textContent = option;
        button.addEventListener('click', () => {
            chatInput.value = option;
            handleUserMessage();
        });
        quickReplies.appendChild(button);
    });
    
    chatMessages.appendChild(quickReplies);
    chatMessages.scrollTop = chatMessages.scrollHeight;
}

// Handle user message
function handleUserMessage() {
    const message = chatInput.value.trim();
    if (!message) return;
    
    // Add user message to chat
    addUserMessage(message);
    chatInput.value = '';
    
    // Process the message based on current state
    if (chatState === 'initial') {
        processInitialMessage(message.toLowerCase());
    } else if (chatState === 'awaiting_disease') {
        processDiseaseSelection(message);
    } else if (chatState === 'showing_precautions') {
        processFollowUp(message);
    }
}

// Process initial message from user
function processInitialMessage(message) {
    // Check if message contains any disease or symptom keywords
    const detectedDiseases = [];
    
    // Check for exact disease matches
    Object.keys(diseaseDatabase).forEach(disease => {
        if (message.includes(disease)) {
            detectedDiseases.push(disease);
        }
    });
    
    // Check for symptom matches
    Object.keys(symptomToDisease).forEach(symptom => {
        if (message.includes(symptom) && !detectedDiseases.includes(symptomToDisease[symptom])) {
            detectedDiseases.push(symptomToDisease[symptom]);
        }
    });
    
    if (detectedDiseases.length > 0) {
        // If we found matching diseases, show the first one
        showDiseasePrecautions(diseaseDatabase[detectedDiseases[0]]);
    } else {
        // Otherwise, ask the user to select a disease
        askForDisease();
    }
}

// Ask user to select a disease
function askForDisease() {
    chatState = 'awaiting_disease';
    
    const diseaseOptions = document.createElement('div');
    diseaseOptions.className = 'disease-options';
    
    // Add common options
    const commonDiseases = ['Fever', 'Common Cold', 'Headache', 'Stomach Pain', 'Cough'];
    
    commonDiseases.forEach(disease => {
        const option = document.createElement('div');
        option.className = 'disease-option';
        option.textContent = disease;
        option.addEventListener('click', () => {
            processDiseaseSelection(disease);
        });
        diseaseOptions.appendChild(option);
    });
    
    addBotMessage('I understand you\'re not feeling well. Could you tell me what symptoms you\'re experiencing or select from these common issues?', diseaseOptions);
}

// Process disease selection
function processDiseaseSelection(message) {
    const lowerMessage = message.toLowerCase();
    let foundDisease = null;
    
    // Check for exact matches first
    Object.keys(diseaseDatabase).forEach(disease => {
        if (lowerMessage.includes(disease)) {
            foundDisease = diseaseDatabase[disease];
        }
    });
    
    // If no exact match, check for symptom matches
    if (!foundDisease) {
        Object.keys(symptomToDisease).forEach(symptom => {
            if (lowerMessage.includes(symptom)) {
                foundDisease = diseaseDatabase[symptomToDisease[symptom]];
            }
        });
    }
    
    if (foundDisease) {
        showDiseasePrecautions(foundDisease);
    } else {
        // If we still can't identify the disease, show a generic response
        addBotMessage('I\'m not sure I understand. Could you describe your symptoms in more detail?');
        chatState = 'initial';
    }
}

// Show precautions for a specific disease
function showDiseasePrecautions(disease) {
    chatState = 'showing_precautions';
    selectedDisease = disease;
    
    const precautionsList = disease.precautions.map(p => `• ${p}`).join('\n');
    
    addBotMessage(`For ${disease.name}, here are some important precautions you should take:\n\n${precautionsList}\n\nRemember, this is general advice. Please consult a healthcare professional for a proper diagnosis and treatment plan.`);
    
    // Add follow-up question
    setTimeout(() => {
        const quickReplies = document.createElement('div');
        quickReplies.className = 'quick-replies';
        
        const options = ['Search for hospitals', 'Ask another question', 'Thank you!'];
        options.forEach(option => {
            const button = document.createElement('div');
            button.className = 'quick-reply';
            button.textContent = option;
            button.addEventListener('click', () => {
                if (option === 'Search for hospitals') {
                    window.location.href = '/hospitals';
                } else if (option === 'Ask another question') {
                    chatState = 'initial';
                    addBotMessage('What else would you like to know about?');
                } else {
                    chatState = 'initial';
                    addBotMessage('You\'re welcome! Feel free to ask if you have any more questions.');
                    setTimeout(showWelcomeMessage, 1500);
                }
            });
            quickReplies.appendChild(button);
        });
        
        chatMessages.appendChild(quickReplies);
        chatMessages.scrollTop = chatMessages.scrollHeight;
    }, 500);
}

// Process follow-up messages
function processFollowUp(message) {
    const lowerMessage = message.toLowerCase();
    
    if (lowerMessage.includes('thank') || lowerMessage.includes('thanks')) {
        addBotMessage('You\'re welcome! Feel free to ask if you have any more questions.');
        setTimeout(showWelcomeMessage, 1500);
    } else if (lowerMessage.includes('hospital') || lowerMessage.includes('doctor')) {
        window.location.href = '/hospitals';
    } else {
        // If we don't understand the follow-up, reset to initial state
        chatState = 'initial';
        addBotMessage('I\'m not sure I understand. How else can I help you today?');
    }
}

// Add a message from the bot to the chat
function addBotMessage(text, element = null) {
    const messageDiv = document.createElement('div');
    messageDiv.className = 'message bot-message';
    messageDiv.textContent = text;
    
    chatMessages.appendChild(messageDiv);
    
    if (element) {
        chatMessages.appendChild(element);
    }
    
    chatMessages.scrollTop = chatMessages.scrollHeight;
}

// Add a message from the user to the chat
function addUserMessage(text) {
    const messageDiv = document.createElement('div');
    messageDiv.className = 'message user-message';
    messageDiv.textContent = text;
    
    chatMessages.appendChild(messageDiv);
    chatMessages.scrollTop = chatMessages.scrollHeight;
}

// Initialize the chatbot when the DOM is loaded
document.addEventListener('DOMContentLoaded', initChatbot);
