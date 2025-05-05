import { Routes, Route } from 'react-router-dom';
import Home from './pages/home';
import ToolPage from './pages/toolpage';

const App = () => {
  return (
    <Routes>
      <Route path="/" element={<Home />} />
      <Route path="/tool" element={<ToolPage />} />
    </Routes>
  );
};

export default App;