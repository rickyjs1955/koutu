// src/App.tsx
import React, { useState } from 'react'

const App: React.FC = () => {
  const [currentPage, setCurrentPage] = useState('home')

  return (
    <div style={{ 
      minHeight: '100vh', 
      fontFamily: 'Arial, sans-serif',
      backgroundColor: '#f5f5f5'
    }}>
      {/* Header */}
      <header style={{
        backgroundColor: '#2563eb',
        color: 'white',
        padding: '1rem 2rem',
        boxShadow: '0 2px 4px rgba(0,0,0,0.1)'
      }}>
        <div style={{ 
          maxWidth: '1200px', 
          margin: '0 auto',
          display: 'flex',
          justifyContent: 'space-between',
          alignItems: 'center'
        }}>
          <h1 style={{ margin: 0, fontSize: '1.8rem' }}>
            👗 Koutu
          </h1>
          <nav>
            <button 
              onClick={() => setCurrentPage('home')}
              style={{
                backgroundColor: currentPage === 'home' ? '#1d4ed8' : 'transparent',
                color: 'white',
                border: 'none',
                padding: '0.5rem 1rem',
                margin: '0 0.25rem',
                borderRadius: '0.25rem',
                cursor: 'pointer'
              }}
            >
              Home
            </button>
            <button 
              onClick={() => setCurrentPage('images')}
              style={{
                backgroundColor: currentPage === 'images' ? '#1d4ed8' : 'transparent',
                color: 'white',
                border: 'none',
                padding: '0.5rem 1rem',
                margin: '0 0.25rem',
                borderRadius: '0.25rem',
                cursor: 'pointer'
              }}
            >
              Images
            </button>
            <button 
              onClick={() => setCurrentPage('garments')}
              style={{
                backgroundColor: currentPage === 'garments' ? '#1d4ed8' : 'transparent',
                color: 'white',
                border: 'none',
                padding: '0.5rem 1rem',
                margin: '0 0.25rem',
                borderRadius: '0.25rem',
                cursor: 'pointer'
              }}
            >
              Garments
            </button>
            <button 
              onClick={() => setCurrentPage('login')}
              style={{
                backgroundColor: '#10b981',
                color: 'white',
                border: 'none',
                padding: '0.5rem 1rem',
                margin: '0 0.25rem',
                borderRadius: '0.25rem',
                cursor: 'pointer'
              }}
            >
              Login
            </button>
          </nav>
        </div>
      </header>

      {/* Main Content */}
      <main style={{
        maxWidth: '1200px',
        margin: '0 auto',
        padding: '2rem'
      }}>
        {currentPage === 'home' && (
          <div style={{ textAlign: 'center', padding: '3rem' }}>
            <h2 style={{ fontSize: '2.5rem', marginBottom: '1rem', color: '#1f2937' }}>
              Welcome to Koutu! 👋
            </h2>
            <p style={{ fontSize: '1.2rem', color: '#6b7280', marginBottom: '2rem' }}>
              Your AI-powered fashion management platform
            </p>
            <div style={{
              display: 'grid',
              gridTemplateColumns: 'repeat(auto-fit, minmax(250px, 1fr))',
              gap: '1rem',
              marginTop: '2rem'
            }}>
              <div style={{
                backgroundColor: 'white',
                padding: '1.5rem',
                borderRadius: '0.5rem',
                boxShadow: '0 2px 4px rgba(0,0,0,0.1)'
              }}>
                <h3 style={{ color: '#2563eb' }}>📸 Upload Images</h3>
                <p>Upload your fashion photos and let AI analyze them</p>
              </div>
              <div style={{
                backgroundColor: 'white',
                padding: '1.5rem',
                borderRadius: '0.5rem',
                boxShadow: '0 2px 4px rgba(0,0,0,0.1)'
              }}>
                <h3 style={{ color: '#2563eb' }}>👕 Create Garments</h3>
                <p>Extract and categorize garments from your images</p>
              </div>
              <div style={{
                backgroundColor: 'white',
                padding: '1.5rem',
                borderRadius: '0.5rem',
                boxShadow: '0 2px 4px rgba(0,0,0,0.1)'
              }}>
                <h3 style={{ color: '#2563eb' }}>🎯 ML Export</h3>
                <p>Export your data for machine learning training</p>
              </div>
            </div>
          </div>
        )}

        {currentPage === 'images' && (
          <div>
            <h2>📸 Images</h2>
            <div style={{
              backgroundColor: 'white',
              padding: '2rem',
              borderRadius: '0.5rem',
              boxShadow: '0 2px 4px rgba(0,0,0,0.1)',
              textAlign: 'center'
            }}>
              <p>Image upload and management will go here</p>
              <button style={{
                backgroundColor: '#2563eb',
                color: 'white',
                border: 'none',
                padding: '0.75rem 1.5rem',
                borderRadius: '0.25rem',
                cursor: 'pointer',
                fontSize: '1rem'
              }}>
                Upload Image
              </button>
            </div>
          </div>
        )}

        {currentPage === 'garments' && (
          <div>
            <h2>👕 Garments</h2>
            <div style={{
              backgroundColor: 'white',
              padding: '2rem',
              borderRadius: '0.5rem',
              boxShadow: '0 2px 4px rgba(0,0,0,0.1)',
              textAlign: 'center'
            }}>
              <p>Garment management will go here</p>
              <button style={{
                backgroundColor: '#10b981',
                color: 'white',
                border: 'none',
                padding: '0.75rem 1.5rem',
                borderRadius: '0.25rem',
                cursor: 'pointer',
                fontSize: '1rem'
              }}>
                Create Garment
              </button>
            </div>
          </div>
        )}

        {currentPage === 'login' && (
          <div style={{ maxWidth: '400px', margin: '0 auto' }}>
            <h2>🔐 Login</h2>
            <div style={{
              backgroundColor: 'white',
              padding: '2rem',
              borderRadius: '0.5rem',
              boxShadow: '0 2px 4px rgba(0,0,0,0.1)'
            }}>
              <div style={{ marginBottom: '1rem' }}>
                <label style={{ display: 'block', marginBottom: '0.5rem' }}>Email:</label>
                <input 
                  type="email" 
                  placeholder="your@email.com"
                  style={{
                    width: '100%',
                    padding: '0.5rem',
                    border: '1px solid #d1d5db',
                    borderRadius: '0.25rem',
                    fontSize: '1rem'
                  }}
                />
              </div>
              <div style={{ marginBottom: '1.5rem' }}>
                <label style={{ display: 'block', marginBottom: '0.5rem' }}>Password:</label>
                <input 
                  type="password" 
                  placeholder="••••••••"
                  style={{
                    width: '100%',
                    padding: '0.5rem',
                    border: '1px solid #d1d5db',
                    borderRadius: '0.25rem',
                    fontSize: '1rem'
                  }}
                />
              </div>
              <button style={{
                width: '100%',
                backgroundColor: '#2563eb',
                color: 'white',
                border: 'none',
                padding: '0.75rem',
                borderRadius: '0.25rem',
                cursor: 'pointer',
                fontSize: '1rem'
              }}>
                Login
              </button>
            </div>
          </div>
        )}
      </main>

      {/* Footer */}
      <footer style={{
        backgroundColor: '#1f2937',
        color: 'white',
        padding: '1rem',
        textAlign: 'center',
        marginTop: '2rem'
      }}>
        <p>Koutu - AI Fashion Platform © 2024</p>
      </footer>
    </div>
  )
}

export default App