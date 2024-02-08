import React, { useState } from 'react';
import Container from 'react-bootstrap/Container';
import Nav from 'react-bootstrap/Nav';
import Navbar from 'react-bootstrap/Navbar';
import NavDropdown from 'react-bootstrap/NavDropdown';
import { Button, TextField, Typography } from "@mui/material"
import PublishIcon from '@mui/icons-material/Publish';
import DeleteForeverIcon from '@mui/icons-material/DeleteForever';
import InputAdornment from '@mui/material/InputAdornment';
import SchoolIcon from '@mui/icons-material/School';
import AccountCircle from '@mui/icons-material/AccountCircle';
import PersonPinIcon from '@mui/icons-material/PersonPin';
import MailOutlineIcon from '@mui/icons-material/MailOutline';
import '../node_modules/bootstrap/dist/css/bootstrap.min.css';
import './html.css'
import Box from '@mui/material/Box';
import InputLabel from '@mui/material/InputLabel';
import MenuItem from '@mui/material/MenuItem';
import FormControl from '@mui/material/FormControl';
import Select from '@mui/material/Select';
import CloudUploadIcon from '@mui/icons-material/CloudUpload';
import DeleteIcon from '@mui/icons-material/Delete';
import SendIcon from '@mui/icons-material/Send'

const Page1 = () => <div className="" style={{backgroundColor:'#e6f7ff',backgroundImage: 'url(IMG_20230708_163943.jpg)',backgroundAttachment:'fixed',backgroundRepeat:'no-repeat'}}>
<div className="container align-self-center pt-5 pe-5 col-10 pb-5 bg-light col-xxl-5 col-xl-6 col-lg-7 col-md-8 my-3  rounded-4 col-5 shadow-lg" style={{ backgroundColor: 'white' }}>
    <h1>EVENT PROPOSAL</h1>
    <br />
    
    <br />
    <h3>TechTalks to be delivered Multidiciplinary Lectures</h3><br />
    <form name="signup" >
    
    <span className="text-danger" id="errsem"></span><br />
<Box sx={{ minWidth: 120 }}>
  <FormControl fullWidth>
    <TextField
            name="facultyName" 
            label="faculty name"
            variant="outlined"
        />
  </FormControl>
</Box>            


 <Box sx={{ minWidth: 120 }}>
  <FormControl fullWidth>
    <InputLabel id="demo-simple-select-label">Academic Year</InputLabel>
    <Select
    labelId="demo-simple-select-label"
    id="demo-simple-select"
    label="Academic Year"
>
    <MenuItem value={2022-23}>2022-23</MenuItem>
    <MenuItem value={2023-2024}>2023-2024</MenuItem>
    </Select>
  </FormControl>
 </Box>


<span className="text-danger" id="errselectone"></span><br />
<Box sx={{ minWidth: 120 }}>
  <FormControl fullWidth>
    <InputLabel id="demo-simple-select-label">Lecture Delivered to Branch</InputLabel>
    <Select
    labelId="demo-simple-select-label"
    id="demo-simple-select"
    label="Lecture Delivered to Branch"
>
    <MenuItem value={"Select the Branch"}>Select the Branch</MenuItem>
    <MenuItem value={"B.E"}>B.E</MenuItem>
    </Select>
  </FormControl>
</Box>

<span className="text-danger" id="errselectone"></span><br />
<Box sx={{ minWidth: 120 }}>
  <FormControl fullWidth>
    <InputLabel id="demo-simple-select-label">Semester</InputLabel>
    <Select
    labelId="demo-simple-select-label"
    id="demo-simple-select"
    label="Semester"
>
    <MenuItem value={"Odd Sem"}>odd Sem</MenuItem>
    <MenuItem value={"Even Sem"}>Even Sem</MenuItem>
    </Select>
  </FormControl>
</Box>

        
       
<span className="text-danger" id="errfname"></span><br />
<Box sx={{ minWidth: 120 }}>
  <FormControl fullWidth>
    <InputLabel id="demo-simple-select-label">Section</InputLabel>
    <Select
    labelId="demo-simple-select-label"
    id="demo-simple-select"
    label="Section"
>
    <MenuItem value={"Select the Section"}>Select the Section</MenuItem>
    <MenuItem value={"A"}>A</MenuItem>
    <MenuItem value={"B"}>B</MenuItem>
    <MenuItem value={"C"}>C</MenuItem>
    </Select>
  </FormControl>
</Box>

<span className="text-danger" id="errfname"></span><br />
<Box sx={{ minWidth: 120 }}>
  <FormControl fullWidth>
    <InputLabel id="demo-simple-select-label">Period</InputLabel>
    <Select
    labelId="demo-simple-select-label"
    id="demo-simple-select"
    label="Period"
>
    <MenuItem value={"Select the Period"}>Select the Period</MenuItem>
    <MenuItem value={"1"}>1</MenuItem>
    <MenuItem value={"2"}>2</MenuItem>
    <MenuItem value={"3"}>3</MenuItem>
    <MenuItem value={"4"}>4</MenuItem>
    <MenuItem value={"5"}>5</MenuItem>
    <MenuItem value={"6"}>6</MenuItem>
    <MenuItem value={"7"}>7</MenuItem>
    <MenuItem value={"8"}>8</MenuItem>
    <MenuItem value={"9"}>9</MenuItem>
    </Select>
  </FormControl>
</Box>

<span className="text-danger" id="errsem"></span><br />
<Box sx={{ minWidth: 120 }}>
  <FormControl fullWidth>
    <TextField
            name="Topic of Discussion" 
            label="Topic of Discussion"
            variant="outlined"
        />
  </FormControl>
</Box>           

<span className="text-danger" id="errsem"></span><br />
<Box sx={{ minWidth: 120 }}>
  <FormControl fullWidth>
    <TextField
            name="Details of the Discussion made" 
            label="Details of the Discussion made"
            variant="outlined"
        />
  </FormControl>
</Box>            



        
        <span className="text-danger" id="erryear"></span><br />
        <Box sx={{ minWidth: 120 }}>
          <FormControl fullWidth>
        <TextField         
            name="Session" 
            label="Session"
            variant="outlined"
        />
        </FormControl>
        </Box>
             
        
        <span id="errlname" className="text-danger"></span><br />
    <Box sx={{ minWidth: 120 }}>
        <FormControl fullWidth>
        <TextField
                       
            name="courseName"
            label="Course Name"
            variant="outlined"
        />
        </FormControl>
    </Box>

       <span id="errcontact" className="text-danger"></span><br />
    <Box sx={{ minWidth: 120 }}>
       <FormControl fullWidth>
        <TextField
                       
            name="Score Obtained"
            label="score Obtained"
            variant="outlined"
        />
        </FormControl>
    </Box>
        <span id="erremail" className="text-danger"></span><br />
        <Box sx={{ minWidth: 120 }}>
  <FormControl fullWidth>
    <InputLabel id="demo-simple-select-label">Certificate Type</InputLabel>
    <Select
    labelId="demo-simple-select-label"
    id="demo-simple-select"
    label="Certificate Type"
>
    <MenuItem value={"GOLD"}>Gold</MenuItem>
    <MenuItem value={"Silver"}>Silver</MenuItem>
    <MenuItem value={"Elite"}>Elite</MenuItem>
    <MenuItem value={"Successfully Completed"}>successfully completed</MenuItem>
    </Select>
  </FormControl>
</Box>

<br/>
<div className='text-center'>
        <br/>
            <Button component="label" variant="contained" startIcon={<CloudUploadIcon />}>
             Upload file
            </Button>
            </div>
        <br/>
        <br/>

<div className='row text-center'>
        <br/>
          <div className="col justify-content-start mt-md-me-1">
          <Button variant="outlined" startIcon={<DeleteIcon />}>
             Clear
          </Button>
          </div>
          <br/>
          <div className=" col justify-content-start md-2">
          <Button variant="contained" endIcon={<SendIcon />}>
             Sumbit
          </Button>
          </div>
          <br/>
        
        <span id="errcertificate" className="text-danger"></span><br />
        </div>

   

        
    </form>
</div>
</div>;








const Page2 = () => 
<div style={{backgroundColor:'#e6f7ff',backgroundImage: 'url(IMG_20230708_163943.jpg)'}} >
<div className="container-fluid "  >
<div className="row justify-content-center">
    <div className="col-7 m-5 shadow-lg rounded-4 " style={{backgroundColor:'white'}}>
        <div className="row bg-body-secondary rounded-4" >
            <Typography variant="h4" className="m-3" color="secondary" >
                Participation in Taste
            </Typography>
        </div>
        <div className="row ps-5">
        <TextField
        className="col-10 m-3"
        name="name"
        label="Name Of The Faculity Participated"
        variant="outlined"        
        InputProps={{
            endAdornment: (
              <InputAdornment >
                <AccountCircle />
              </InputAdornment>
            )
          }}    
          helperText="Alphabetic Charecters Only"  
        />
        <TextField
            className="col-10 m-3"
            name="date"
            label="Date"
            variant="outlined"
            focused      
            type="date"
            helperText="Date Of The Event"
        />
         <TextField
            className="col-10 m-3"
            name="topic"
            label="Seminar topic"
            InputProps={{
                endAdornment:(
                    <SchoolIcon/>
                )
            }}
            variant="outlined"             
        />
        <TextField
            className="col-10 m-3"
            name="taste"
            label="Taste Number"
            variant="outlined"    
            type="number"   
            helperText="Numbers Only"            
        /> 
        <TextField
            className="col-10 m-3"
            name="person"
            label="Resourse Person Name"
            variant="outlined"    
            InputProps={{
                endAdornment:(
                    <PersonPinIcon/>
                )
            }}               
        />
         <TextField
            className="col-10 m-3"
            name="outcome"
            label="Outcome Of The Activity"
            multiline
            rows={4}
            variant="outlined"
            InputProps={{
                endAdornment:(
                    <MailOutlineIcon/>
                )
            }}                 
        />
        </div>
        <div className="row justify-content-around ">
            <Button variant="contained" className="col-2 mb-3" color="success" startIcon={<PublishIcon/>} >Submit</Button>
            <Button variant="outlined" className="col-2 mb-3" color="error" startIcon={<DeleteForeverIcon/>}>Clear</Button>

        </div>
    </div>
</div>
</div>
</div>;




const Page3 = () => <div>This is Page 3</div>;

const PageSelector = () => {
  const [currentPage, setCurrentPage] = useState(null);

  const handleClick = (page) => {
    setCurrentPage(page);
  };

  return (
    <>
    <div>


      <Navbar collapseOnSelect expand="lg" className="bg-body-white">
      <Container fluid className=''>
        <Navbar.Brand href="#home" className=' col-md-6 col-xl-4 col-lg-3'>
                        <img src="main-logo (1).png" alt="Your Logo" className="img-fluid" /></Navbar.Brand>
        <Navbar.Toggle aria-controls="responsive-navbar-nav" />
        <Navbar.Collapse id="responsive-navbar-nav">
          <div className='container'>
          <Nav>
            <div className='col-lg-4'>
            <span className='text-success font-weight-bold responsive-font fs-5'>Name:Dr.Arjun Rajput</span>
            </div>
            <div className='col-lg-2 ms-3 col-xl-2 my-1' >
            <span className='text-success font-weight-bold  responsive-font fs-5'>ID: 6064</span>
            </div>
            <div className='col-lg-1 col-xl-1'>
            <NavDropdown title="ECR" id="collapsible-nav-dropdown">
              <NavDropdown.Item href="#action/3.1">ECR-1</NavDropdown.Item>
              <NavDropdown.Item href="/Content" >
                ECR-2
              </NavDropdown.Item>
              <NavDropdown.Item href="#action/3.3">ECR-3</NavDropdown.Item>
              <NavDropdown.Item href="#action/3.4">
                ECR-4
              </NavDropdown.Item>
            </NavDropdown>
            </div>
            <div className='col-lg-1 col-xxl-1'>
            <NavDropdown title="setAF" id="collapsible-nav-dropdown">
              <NavDropdown.Item href="#action/3.1">Journal Publication</NavDropdown.Item>
              <NavDropdown.Item href="#action/3.2">
                Confrence Publication and Presentations
              </NavDropdown.Item>
              <NavDropdown.Item href="#action/3.3">Workshop and Seminar</NavDropdown.Item>
              <NavDropdown.Item onClick={() => handleClick(<Page1 />)}>
                TechTalks to be delivered Multidiciplinary Lectures
              </NavDropdown.Item >
              <NavDropdown.Item  onClick={() => handleClick(<Page2 />)} >
                Faculty Guest Talk in another institutions
              </NavDropdown.Item>
              <NavDropdown.Item href="#action/3.4">
                NPTEL Certifications
              </NavDropdown.Item>
              <NavDropdown.Item href="#action/3.5">
                Participation in TASTE
              </NavDropdown.Item>
              <NavDropdown.Item href="#action9/3.8">
                e-Certificate(VIDEO LECTURE)
              </NavDropdown.Item>
              <NavDropdown.Item href="#action/3.9">visit to industries,institutions
              </NavDropdown.Item>
              <NavDropdown.Item href="#action/3.10">
                Seed Money Proposal For Research
              </NavDropdown.Item>
              <NavDropdown.Item href="#action/3.11">
                Awards at National,International Level
              </NavDropdown.Item>
              <NavDropdown.Item href="#action/3.12">
                Proposal Submission for Grants
              </NavDropdown.Item>
              <NavDropdown.Item href="#action/3.13">
                Books,Chapter Authership
              </NavDropdown.Item>
              <NavDropdown.Item href="#action/3.14">
                Consultancy and Corporate Training done for Revenue Generation
              </NavDropdown.Item>
              <NavDropdown.Item href="#action/3.15">
                Patents Filled,Pulished,Granted
              </NavDropdown.Item>
              <NavDropdown.Item href="#action/3.16">
                Collaborative Activities with Mou Signed Industries,institutions
              </NavDropdown.Item>
              <NavDropdown.Item href="#action/3.17">
                Visit to the Library
              </NavDropdown.Item>
              <NavDropdown.Item href="#action/3.18">
                Students Motivation for Paper Presentation,Project Submission,Other Contest
              </NavDropdown.Item>
              <NavDropdown.Item href="#action/3.19">
                Professional Society Membership
              </NavDropdown.Item>
              <NavDropdown.Item href="#action/3.20">
                Students Field Work,Internship Guidance
              </NavDropdown.Item>
            </NavDropdown>
            </div>
            <div className='col-lg-2'>
            <NavDropdown title="SESTA" id="collapsible-nav-dropdown">
              <NavDropdown.Item href="#action/3.1">SESTA-1</NavDropdown.Item>
              <NavDropdown.Item href="#action/3.2">
                SESTA-2
              </NavDropdown.Item>
              <NavDropdown.Item href="#action/3.3">SESTA-3</NavDropdown.Item>
              <NavDropdown.Item href="#action/3.4">
                SESTA-4
              </NavDropdown.Item>
            </NavDropdown>
            </div>
            <div className='col-lg-1'>
            <a class=" btn btn-outline-danger border-danger" href="#">LogOut</a>
            </div>
      
          </Nav>
          </div>
        </Navbar.Collapse>
      </Container>
    </Navbar>






      {/* */}
      {currentPage}
    </div>
    </>
  );
};

export default PageSelector;

