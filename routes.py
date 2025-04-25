from flask import render_template, request, redirect, url_for, flash, session, jsonify
from models import (
    db, 
    Admin, 
    Service, 
    Professional, 
    Customer, 
    ServiceRequest, 
    ProfessionalRating,
    ProfessionalService
)
from app import app
from sqlalchemy.orm import joinedload
from flask_login import current_user
from collections import Counter
from datetime import date, datetime, timedelta
from sqlalchemy import cast, Date, func, text
import os
from werkzeug.utils import secure_filename
from werkzeug.security import check_password_hash, generate_password_hash
from functools import wraps
from flask import abort
import logging
import sys
import traceback
from flask_login import login_required
from flask import session
import secrets

@app.route('/')
def index():
    services = Service.query.all()
    return render_template('index.html', services=services)

@app.route('/services')
def services():
    services = Service.query.filter_by(is_active=True).all()
    return render_template('services.html', services=services)

@app.context_processor
def inject_current_user():
    return dict(current_user=current_user)

@app.route('/customer/login', methods=['GET', 'POST'])
def customer_login():
    if request.method == 'POST':
        email = request.form.get('email', '').strip()
        password = request.form.get('password', '')
        
        customer = Customer.query.filter_by(email=email).first()
        
        if customer and customer.check_password(password):
            session['user_id'] = customer.customer_id
            session['user_type'] = 'customer'
            session['email'] = customer.email
            session.permanent = True
            
            flash('Login successful!', 'success')
            return redirect(url_for('customer_dashboard'))
        else:
            flash('Invalid email or password', 'danger')
            return redirect(url_for('customer_login'))
    
    return render_template('customer/login.html')

@app.route('/customer/register', methods=['GET', 'POST'])
def customer_register():
    if request.method == 'POST':
        try:
            full_name = request.form.get('full_name', '').strip()
            email = request.form.get('email', '').strip()
            phone = request.form.get('phone', '').strip()
            address = request.form.get('address', '').strip()
            password = request.form.get('password', '')
            confirm_password = request.form.get('confirm_password', '')
            
            if not all([full_name, email, phone, address, password, confirm_password]):
                flash('All fields are required', 'danger')
                return redirect(url_for('customer_register'))
            
            if password != confirm_password:
                flash('Passwords do not match', 'danger')
                return redirect(url_for('customer_register'))
            
            if Customer.query.filter_by(email=email).first():
                flash('Email already registered', 'danger')
                return redirect(url_for('customer_register'))
            
            new_customer = Customer(
                full_name=full_name,
                email=email,
                phone=phone,
                address=address
            )
            new_customer.set_password(password)
            
            db.session.add(new_customer)
            db.session.commit()
            
            flash('Registration successful! Please login.', 'success')
            return redirect(url_for('customer_login'))
            
        except Exception as e:
            db.session.rollback()
            print(f"Error in registration: {str(e)}")
            flash('An error occurred during registration', 'danger')
            return redirect(url_for('customer_register'))
    
    return render_template('customer/register.html')

@app.route('/customer/dashboard')
def customer_dashboard():
    if 'user_id' not in session or session['user_type'] != 'customer':
        flash('Please login first', 'warning')
        return redirect(url_for('customer_login'))
    
    try:
        # Get customer using user_id from session
        customer = Customer.query.get_or_404(session['user_id'])
        
        # Get all service requests for this customer
        service_requests = ServiceRequest.query.filter_by(
            customer_id=customer.customer_id
        ).order_by(ServiceRequest.request_date.desc()).all()
        
        # Get completed services that need rating
        pending_ratings = [
            request for request in service_requests 
            if request.status == 'Completed' and not request.professional_rating
        ]
        
        # Calculate stats
        stats = {
            'total_requests': len(service_requests),
            'completed_requests': sum(1 for r in service_requests if r.status == 'Completed'),
            'pending_requests': sum(1 for r in service_requests if r.status == 'Pending'),
            'active_requests': sum(1 for r in service_requests if r.status == 'Accepted')
        }
        
        return render_template('customer/dashboard.html',
                             customer=customer,
                             service_requests=service_requests,
                             pending_ratings=pending_ratings,
                             stats=stats)
                             
    except Exception as e:
        print(f"Dashboard error: {str(e)}")
        flash('Error loading dashboard', 'danger')
        return redirect(url_for('customer_login'))

@app.route('/customer/service-history')
def view_service_history():
    customer_id = session.get('customer_id')
    if not customer_id:
        flash("Please login to view your service history", "warning")
        return redirect(url_for('customer_login'))

    # Fetch all service requests with related data
    service_requests = (
        ServiceRequest.query
        .filter_by(customer_id=customer_id)
        .options(
            joinedload(ServiceRequest.service),
            joinedload(ServiceRequest.professional)
        )
        .all()
    )

    # For each request, fetch the rating if it exists
    for request in service_requests:
        request.rating_entry = ProfessionalRating.query.filter_by(
            customer_id=customer_id,
            service_id=request.service_id
        ).first()

    return render_template('customer/service_history.html', service_requests=service_requests)

from flask import jsonify

@app.route('/customer/summary')
def summary_page():
    # Render the HTML page
    return render_template('customer/summary.html')

@app.route('/api/service-requests')
def service_requests_data():
    # Example aggregation query for service requests by status
    results = db.session.query(
        ServiceRequest.status, db.func.count(ServiceRequest.request_id)
    ).group_by(ServiceRequest.status).all()
    
    data = [{"status": row[0], "count": row[1]} for row in results]
    return jsonify(data)

@app.route('/api/customer-ratings')
def customer_ratings_data():
    # Example aggregation query for ratings distribution
    results = db.session.query(
        ProfessionalRating.rating, db.func.count(ProfessionalRating.rating_id)
    ).group_by(ProfessionalRating.rating).all()
    
    data = [{"rating": row[0], "count": row[1]} for row in results]
    return jsonify(data)

@app.route('/rate_service/<int:service_id>', methods=['POST'])
def rate_service(service_id):
    customer_id = session.get('customer_id')
    if not customer_id:
        flash("Please log in to rate a service.", "danger")
        return redirect(url_for('customer_login'))

    # Fetch the form data
    rating = request.form.get('rating', type=int)
    review = request.form.get('review', type=str)
    # Check if the rating already exists for the current user and service
    existing_rating = ProfessionalRating.query.filter_by(
        customer_id=customer_id,
        service_id=service_id
    ).first()

    if existing_rating:
        # Update the existing rating
        existing_rating.rating = rating
        existing_rating.review = review
        existing_rating.rating_date = db.func.now()
    else:
        # Create a new rating
        new_rating = ProfessionalRating(
            customer_id=customer_id,
            service_id=service_id,
            rating=rating,
            review=review
        )
        db.session.add(new_rating)
        flash("Your rating has been submitted successfully.", "success")
    
    db.session.commit()

    # Redirect back to the service history page
    return redirect(url_for('view_service_history'))


@app.route('/service/<int:service_id>/details', methods=['GET', 'POST'])
def service_details(service_id):
    if not session.get('customer_id'):
        flash('Please login to request services', 'warning')
        return redirect(url_for('customer_login'))

    service = Service.query.get_or_404(service_id)
    professionals = Professional.query.join(ProfessionalService).filter(
        ProfessionalService.service_id == service_id).all()

    if request.method == 'POST':
        try:
            professional_id = request.form.get('professional_id')
            service_date = request.form.get('service_date')
            service_time = request.form.get('service_time')
            service_location = request.form.get('service_location')
            
            if not all([professional_id, service_date, service_time, service_location]):
                flash('Please fill in all required fields', 'danger')
                return render_template('customer/view_service_details.html',
                                    service=service,
                                    professionals=professionals)

            try:
                service_datetime = datetime.strptime(f"{service_date} {service_time}", "%Y-%m-%d %H:%M")
                
                if service_datetime < datetime.now():
                    flash('Cannot select a past date and time', 'danger')
                    return render_template('customer/view_service_details.html',
                                        service=service,
                                        professionals=professionals)
                
                new_request = ServiceRequest(
                    service_id=service_id,
                    customer_id=session['customer_id'],
                    professional_id=professional_id,
                    request_date=service_datetime.date(),
                    request_time=service_datetime.time(),
                    service_location=service_location,
                    status="Requested"
                )
                
                db.session.add(new_request)
                db.session.commit()
                
                flash('Service request submitted successfully!', 'success')
                return redirect(url_for('customer_dashboard'))
                
            except ValueError:
                flash('Invalid date or time format', 'danger')
                return render_template('customer/view_service_details.html',
                                    service=service,
                                    professionals=professionals)
            
        except Exception as e:
            db.session.rollback()
            flash('Error submitting service request. Please try again.', 'danger')
            print(f"Error: {str(e)}")
            
    return render_template('customer/view_service_details.html',
                         service=service,
                         professionals=professionals)

@app.route('/customer/close_request/<int:request_id>', methods=['POST'])
def close_service_request(request_id):
    customer_id = session.get('customer_id')
    if not customer_id:
        flash("Session expired. Please log in again.", "warning")
        return redirect(url_for('customer_login'))

    service_request = ServiceRequest.query.filter_by(
        request_id=request_id, customer_id=customer_id, status='Accepted'
    ).first()

    if not service_request:
        flash("Invalid request or the request cannot be closed.", "danger")
        return redirect(url_for('view_service_history'))

    # Update the status to Closed
    service_request.status = 'Closed'
    db.session.commit()

    flash("Service request has been successfully closed.", "success")
    return redirect(url_for('view_service_history'))


@app.route('/customer/add-service-request', methods=['POST'])
def add_service_request():
    customer_id = session.get('customer_id')

    if not customer_id:
        flash("You must be logged in to request a service.")
        return redirect(url_for('customer_login'))

    # Get form data
    professional_id = request.form.get('professional_id')
    service_id = request.form.get('service_id')

    if not professional_id or not service_id:
        flash("Please select a professional and ensure the service ID is provided.")
        return redirect(url_for('customer_dashboard'))

    # Fetch professional and service
    professional = Professional.query.get(professional_id)
    service = Service.query.get(service_id)

    if not professional:
        flash("Invalid professional selected.")
        return redirect(url_for('customer_dashboard'))

    if not service:
        flash("Invalid service selected.")
        return redirect(url_for('customer_dashboard'))

    # Create a new service request
    service_request = ServiceRequest(
        customer_id=customer_id,
        professional_id=professional_id,
        service_id=service_id,
        status="Requested",
        request_date=db.func.now()
    )

    try:
        db.session.add(service_request)
        db.session.commit()
        flash("Service request successfully created!")
        return redirect(url_for('view_service_history'))
    except Exception as e:
        db.session.rollback()
        app.logger.error(f"Error creating service request: {e}")
        flash("An error occurred while creating the service request.")
        return redirect(url_for('customer_dashboard'))

@app.route('/customer/profile', methods=['GET', 'POST'])
def customer_profile():
    if 'user_id' not in session or session['user_type'] != 'customer':
        flash('Please login first', 'warning')
        return redirect(url_for('customer_login'))
    
    try:
        # Get customer using user_id from session
        customer = Customer.query.get_or_404(session['user_id'])
        
        if request.method == 'POST':
            # Validate email uniqueness if it's changed
            if customer.email != request.form.get('email'):
                existing_customer = Customer.query.filter_by(email=request.form.get('email')).first()
                if existing_customer:
                    flash('Email already exists', 'danger')
                    return redirect(url_for('customer_profile'))
            
            # Update customer details
            customer.full_name = request.form.get('full_name')
            customer.email = request.form.get('email')
            customer.phone = request.form.get('phone')
            customer.address = request.form.get('address')
            
            # Update password if provided
            new_password = request.form.get('new_password')
            if new_password:
                current_password = request.form.get('current_password')
                if not current_password:
                    flash('Current password is required to set new password', 'danger')
                    return redirect(url_for('customer_profile'))
                    
                if not customer.check_password(current_password):
                    flash('Current password is incorrect', 'danger')
                    return redirect(url_for('customer_profile'))
                    
                customer.set_password(new_password)
            
            try:
                db.session.commit()
                flash('Profile updated successfully', 'success')
            except Exception as e:
                db.session.rollback()
                print(f"Error updating profile: {str(e)}")
                flash('Error updating profile. Please try again.', 'danger')
            
            return redirect(url_for('customer_profile'))
        
        return render_template('customer/profile.html', customer=customer)
        
    except Exception as e:
        print(f"Profile error: {str(e)}")
        flash('Error loading profile', 'danger')
        return redirect(url_for('customer_dashboard'))

@app.route('/customer/logout')
def customer_logout():
    session.clear()
    flash('You have been logged out', 'info')
    return redirect(url_for('index'))

@app.route('/professional/register', methods=['GET', 'POST'])
def professional_register():
    if request.method == 'POST':
        try:
            full_name = request.form.get('full_name', '').strip()
            email = request.form.get('email', '').strip()
            phone = request.form.get('phone', '').strip()
            experience_years = request.form.get('experience_years', type=int)
            password = request.form.get('password', '')
            confirm_password = request.form.get('confirm_password', '')
            
            # Get selected services and their prices
            services = request.form.getlist('services')
            prices = request.form.getlist('prices')
            
            # Validation
            if not all([full_name, email, phone, experience_years, password]):
                flash('Please fill in all required fields', 'danger')
                return redirect(url_for('professional_register'))
                
            if password != confirm_password:
                flash('Passwords do not match', 'danger')
                return redirect(url_for('professional_register'))
                
            if not services:
                flash('Please select at least one service', 'danger')
                return redirect(url_for('professional_register'))
                
            # Check if email already exists
            if Professional.query.filter_by(email=email).first():
                flash('Email already registered', 'danger')
                return redirect(url_for('professional_register'))
            
            # Create new professional
            professional = Professional(
                full_name=full_name,
                email=email,
                phone=phone,
                experience_years=experience_years
            )
            professional.set_password(password)
            
            db.session.add(professional)
            db.session.flush()  # Get professional_id before committing
            
            # Add professional services
            for service_id, price in zip(services, prices):
                if price.strip():  # Only add if price is provided
                    prof_service = ProfessionalService(
                        professional_id=professional.professional_id,
                        service_id=int(service_id),
                        price=float(price)
                    )
                    db.session.add(prof_service)
            
            db.session.commit()
            flash('Registration successful! Please wait for admin verification.', 'success')
            return redirect(url_for('professional_login'))
            
        except Exception as e:
            db.session.rollback()
            print(f"Registration error: {str(e)}")
            flash('An error occurred during registration', 'danger')
            return redirect(url_for('professional_register'))
    
    # Get all services for the registration form
    services = Service.query.all()
    return render_template('professional/register.html', services=services)

@app.route('/professional/login', methods=['GET', 'POST'])
def professional_login():
    if request.method == 'POST':
        email = request.form.get('email', '').strip()
        password = request.form.get('password', '')
        
        professional = Professional.query.filter_by(email=email).first()
        
        if professional and professional.check_password(password):
            if not professional.is_verified:
                flash('Your account is pending verification by admin', 'warning')
                return redirect(url_for('professional_login'))
                
            session['user_id'] = professional.professional_id
            session['user_type'] = 'professional'
            session['email'] = professional.email
            session.permanent = True
            
            flash('Login successful!', 'success')
            return redirect(url_for('professional_dashboard'))
        else:
            flash('Invalid email or password', 'danger')
            return redirect(url_for('professional_login'))
    
    return render_template('professional/login.html')

@app.route('/professional/dashboard')
def professional_dashboard():
    if 'user_id' not in session or session['user_type'] != 'professional':
        flash('Please login first', 'warning')
        return redirect(url_for('professional_login'))
    
    try:
        professional = Professional.query.get_or_404(session['user_id'])
        
        # Get all service requests for this professional
        service_requests = ServiceRequest.query.filter_by(
            professional_id=professional.professional_id
        ).order_by(ServiceRequest.request_date.desc()).all()
        
        # Get professional's services
        professional_services = ProfessionalService.query.filter_by(
            professional_id=professional.professional_id
        ).all()
        
        # Get professional's ratings
        professional_ratings = ProfessionalRating.query.filter_by(
            professional_id=professional.professional_id
        ).order_by(ProfessionalRating.created_at.desc()).all()
        
        # Calculate stats
        stats = {
            'total_requests': len(service_requests),
            'completed_requests': len([r for r in service_requests if r.status == 'Completed']),
            'pending_requests': len([r for r in service_requests if r.status == 'Pending']),
            'active_requests': len([r for r in service_requests if r.status == 'Accepted'])
        }
        
        return render_template('professional/dashboard.html',
                             professional=professional,
                             service_requests=service_requests,
                             professional_services=professional_services,
                             professional_ratings=professional_ratings,
                             stats=stats)
                             
    except Exception as e:
        print(f"Dashboard error: {str(e)}")
        flash('Error loading dashboard', 'danger')
        return redirect(url_for('professional_login'))

@app.route('/professional/update-status/<int:request_id>', methods=['POST'])
def update_request_status(request_id):
    if 'user_id' not in session or session['user_type'] != 'professional':
        return jsonify({'success': False, 'message': 'Unauthorized'}), 401
    
    try:
        service_request = ServiceRequest.query.get_or_404(request_id)
        
        # Verify this request is assigned to the logged-in professional
        if service_request.professional_id != session['user_id']:
            return jsonify({'success': False, 'message': 'Unauthorized access'}), 403

        status = request.form.get('status')
        if status not in ['Accepted', 'Completed', 'Rejected']:
            return jsonify({'success': False, 'message': 'Invalid status'}), 400

        # Update request status
        service_request.status = status
        
        # Add timestamp based on status
        if status == 'Accepted':
            service_request.accepted_at = datetime.utcnow()
        elif status == 'Completed':
            service_request.completed_at = datetime.utcnow()
        elif status == 'Rejected':
            service_request.rejected_at = datetime.utcnow()
        
        db.session.commit()
        
        return jsonify({
            'success': True,
            'message': f'Request {status.lower()} successfully'
        })
        
    except Exception as e:
        db.session.rollback()
        print(f"Status update error: {str(e)}")
        return jsonify({'success': False, 'message': 'Error updating status'}), 500

@app.route('/professional/accept/<int:request_id>')
def accept_request(request_id):
    professional_id = session.get('professional_id')

    if not professional_id:
        flash("You must be logged in to perform this action.")
        return redirect(url_for('professional_login'))

    request = ServiceRequest.query.filter_by(request_id=request_id, professional_id=professional_id).first_or_404()
    request.status = 'Accepted'
    db.session.commit()

    flash("Service request accepted.")
    return redirect(url_for('professional_dashboard'))

@app.route('/professional/close/<int:request_id>')
def close_request(request_id):
    professional_id = session.get('professional_id')

    if not professional_id:
        flash("You must be logged in to perform this action.")
        return redirect(url_for('professional_login'))

    request = ServiceRequest.query.filter_by(request_id=request_id, professional_id=professional_id).first_or_404()
    request.status = 'Closed'
    db.session.commit()

    flash("Service request marked as closed.")
    return redirect(url_for('professional_dashboard'))

@app.route('/professional/professional_profile')
def professional_profile():
    if 'professional_id' not in session:
        return redirect(url_for('professional_login'))  # Redirect if not logged in
    
    # Fetch professional details from the database
    professional = Professional.query.get(session['professional_id'])
    
    if not professional:
        return redirect(url_for('professional_login'))
    
    return render_template('/professional/professional_profile.html', professional=professional)

@app.route('/logout')
def logout():
    session.clear()
    flash('You have been logged out successfully.', 'info')
    return redirect(url_for('index'))

@app.route('/admin/login', methods=['GET', 'POST'])
def admin_login():
    if request.method == 'POST':
        email = request.form.get('email')
        password = request.form.get('password')
        
        admin = Admin.query.filter_by(email=email).first()
        
        if admin and admin.check_password(password):
            session['user_id'] = admin.admin_id
            session['user_type'] = 'admin'
            flash('Login successful!', 'success')
            return redirect(url_for('admin_dashboard'))
        else:
            flash('Invalid email or password', 'danger')
    
    return render_template('admin/login.html')

@app.route('/admin/dashboard')
def admin_dashboard():
    if 'user_id' not in session or session['user_type'] != 'admin':
        return redirect(url_for('admin_login'))
        
    # Basic stats
    total_customers = Customer.query.count()
    total_professionals = Professional.query.count()
    total_services = Service.query.count()
    total_bookings = ServiceRequest.query.count()
    
    # Recent bookings
    recent_bookings = ServiceRequest.query.order_by(ServiceRequest.request_date.desc()).limit(10).all()
    
    # Pending verifications
    pending_verifications = Professional.query.filter_by(is_verified=False).count()
    
    # Booking status counts
    completed_bookings = ServiceRequest.query.filter_by(status='Completed').count()
    pending_bookings = ServiceRequest.query.filter_by(status='Pending').count()
    cancelled_bookings = ServiceRequest.query.filter_by(status='Rejected').count()
    
    # Top services
    top_services = db.session.query(
        Service,
        func.count(ServiceRequest.request_id).label('booking_count')
    ).join(ServiceRequest).group_by(Service).order_by(text('booking_count DESC')).limit(5).all()
    
    return render_template('admin/dashboard.html',
                         total_customers=total_customers,
                         total_professionals=total_professionals,
                         total_services=total_services,
                         total_bookings=total_bookings,
                         recent_bookings=recent_bookings,
                         pending_verifications=pending_verifications,
                         completed_bookings=completed_bookings,
                         pending_bookings=pending_bookings,
                         cancelled_bookings=cancelled_bookings,
                         top_services=top_services)

@app.route('/admin/services')
def admin_services():
    if 'user_type' not in session or session['user_type'] != 'admin':
        flash('Please login as admin first', 'danger')
        return redirect(url_for('admin_login'))
    
    services = Service.query.all()
    return render_template('admin/services.html', services=services)

@app.route('/admin/services/new', methods=['GET', 'POST'])
def admin_add_service():
    if 'user_type' not in session or session['user_type'] != 'admin':
        flash('Please login as admin first', 'danger')
        return redirect(url_for('admin_login'))
    
    if request.method == 'POST':
        service_name = request.form.get('service_name')
        description = request.form.get('description')
        base_price = float(request.form.get('base_price'))
        category = request.form.get('category')
        
        service = Service(
            service_name=service_name,
            description=description,
            base_price=base_price,
            category=category
        )
        
        try:
            db.session.add(service)
            db.session.commit()
            flash('Service added successfully!', 'success')
            return redirect(url_for('admin_services'))
        except Exception as e:
            db.session.rollback()
            flash('Error adding service. Please try again.', 'danger')
    
    return render_template('admin/add_service.html')

@app.route('/admin/services/edit/<int:service_id>', methods=['GET', 'POST'])
def edit_service(service_id):
    if 'user_type' not in session or session['user_type'] != 'admin':
        flash('Please login as admin first', 'danger')
        return redirect(url_for('admin_login'))
    
    service = Service.query.get_or_404(service_id)
    
    if request.method == 'POST':
        service_name = request.form.get('service_name')
        description = request.form.get('description')
        base_price = request.form.get('base_price')
        
        if not all([service_name, description, base_price]):
            flash('All fields are required', 'danger')
            return redirect(url_for('edit_service', service_id=service_id))
        
        try:
            base_price = float(base_price)
            service.service_name = service_name
            service.description = description
            service.base_price = base_price
            
            db.session.commit()
            flash('Service updated successfully', 'success')
            return redirect(url_for('admin_services'))
            
        except ValueError:
            flash('Invalid price format', 'danger')
            return redirect(url_for('edit_service', service_id=service_id))
        except Exception as e:
            db.session.rollback()
            flash('Error updating service', 'danger')
            return redirect(url_for('edit_service', service_id=service_id))
    
    return render_template('admin/edit_service.html', service=service)

@app.route('/admin/services/delete/<int:service_id>', methods=['POST'])
def admin_delete_service(service_id):
    if 'user_type' not in session or session['user_type'] != 'admin':
        flash('Please login as admin first', 'danger')
        return redirect(url_for('admin_login'))
    
    service = Service.query.get_or_404(service_id)
    
    try:
        db.session.delete(service)
        db.session.commit()
        flash('Service deleted successfully!', 'success')
    except Exception as e:
        db.session.rollback()
        flash('Error deleting service. Please try again.', 'danger')
    
    return redirect(url_for('admin_services'))

@app.route('/admin/view_professional/<int:professional_id>')
def view_professional(professional_id):
    professional = Professional.query.get_or_404(professional_id)
    return render_template('admin/view_professional.html', professional=professional)

@app.route('/admin/accept_professional/<int:professional_id>', methods=['POST'])
def accept_professional(professional_id):
    professional = Professional.query.get_or_404(professional_id)
    if not professional.is_approved:
        professional.is_approved = True
        db.session.commit()
        flash(f"Professional {professional.full_name} approved.", "success")
    return redirect(url_for('admin_dashboard'))

@app.route('/admin/reject_professional/<int:professional_id>', methods=['POST'])
def reject_professional(professional_id):
    professional = Professional.query.get_or_404(professional_id)
    db.session.delete(professional)
    db.session.commit()
    flash(f"Professional {professional.full_name} rejected and removed.", "danger")
    return redirect(url_for('admin_dashboard'))

@app.route('/submit-rating/<int:request_id>', methods=['POST'])
def submit_rating(request_id):
    if 'user_id' not in session or session['user_type'] != 'customer':
        return jsonify({'success': False, 'message': 'Unauthorized'}), 401
    
    try:
        service_request = ServiceRequest.query.get_or_404(request_id)
        
        # Verify this request belongs to the logged-in customer
        if service_request.customer_id != session['user_id']:
            return jsonify({'success': False, 'message': 'Unauthorized access'}), 403
            
        # Check if rating already exists
        existing_rating = ProfessionalRating.query.filter_by(request_id=request_id).first()
        if existing_rating:
            return jsonify({'success': False, 'message': 'Rating already submitted'}), 400
            
        # Create new rating
        rating = ProfessionalRating(
            request_id=request_id,
            professional_id=service_request.professional_id,
            customer_id=session['user_id'],
            rating=int(request.form.get('rating')),
            review=request.form.get('review')
        )
        
        db.session.add(rating)
        
        # Update professional's average rating
        professional = Professional.query.get(service_request.professional_id)
        professional.update_rating()
        
        db.session.commit()
        
        return jsonify({
            'success': True,
            'message': 'Rating submitted successfully'
        })
        
    except Exception as e:
        db.session.rollback()
        print(f"Rating submission error: {str(e)}")
        return jsonify({
            'success': False,
            'message': 'Error submitting rating'
        }), 500

@app.route('/professional/logout')
def professional_logout():
    session.clear()
    flash('Professional logged out successfully.', 'info')
    return redirect(url_for('professional_login'))

@app.route('/admin/logout')
def admin_logout():
    session.clear()
    flash('Admin logged out successfully.', 'info')
    return redirect(url_for('admin_login'))

@app.route('/cancel-request/<int:request_id>', methods=['POST'])
def cancel_request(request_id):
    if 'user_id' not in session or session['user_type'] != 'customer':
        return jsonify({'success': False, 'message': 'Unauthorized'}), 401
    
    try:
        service_request = ServiceRequest.query.get_or_404(request_id)
        
        if service_request.customer_id != session['user_id']:
            return jsonify({'success': False, 'message': 'Unauthorized access'}), 403
            
        if service_request.status != 'Pending':
            return jsonify({'success': False, 'message': 'Can only cancel pending requests'}), 400
            
        service_request.status = 'Cancelled'
        db.session.commit()
        
        return jsonify({
            'success': True,
            'message': 'Request cancelled successfully'
        })
        
    except Exception as e:
        db.session.rollback()
        print(f"Cancel error: {str(e)}")
        return jsonify({'success': False, 'message': 'Error cancelling request'}), 500

@app.route('/reject-request/<int:request_id>', methods=['POST'])
def reject_request(request_id):
    if 'user_id' not in session or session['user_type'] != 'professional':
        return jsonify({'success': False, 'message': 'Unauthorized'}), 401
    
    try:
        service_request = ServiceRequest.query.get_or_404(request_id)
        
        if service_request.professional_id != session['user_id']:
            return jsonify({'success': False, 'message': 'Unauthorized access'}), 403
            
        if service_request.status != 'Pending':
            return jsonify({'success': False, 'message': 'Can only reject pending requests'}), 400
            
        service_request.status = 'Rejected'
        db.session.commit()
        
        return jsonify({
            'success': True,
            'message': 'Request rejected successfully'
        })
        
    except Exception as e:
        db.session.rollback()
        print(f"Reject error: {str(e)}")
        return jsonify({'success': False, 'message': 'Error rejecting request'}), 500

@app.route('/admin/professionals')
def admin_professionals():
    if 'user_type' not in session or session['user_type'] != 'admin':
        flash('Please login as admin first', 'danger')
        return redirect(url_for('admin_login'))
    
    professionals = Professional.query.all()
    return render_template('admin/professionals.html', professionals=professionals)

@app.route('/admin/bookings')
def admin_bookings():
    if 'user_type' not in session or session['user_type'] != 'admin':
        flash('Please login as admin first', 'danger')
        return redirect(url_for('admin_login'))
    
    bookings = ServiceRequest.query.order_by(ServiceRequest.request_date.desc()).all()
    return render_template('admin/bookings.html', bookings=bookings)

@app.route('/admin/verify_professional/<int:professional_id>', methods=['GET', 'POST'])
def admin_verify_professional(professional_id):
    if 'user_id' not in session or session['user_type'] != 'admin':
        flash('Please login as admin', 'warning')
        return redirect(url_for('admin_login'))
        
    professional = Professional.query.get_or_404(professional_id)
    
    if request.method == 'POST':
        professional.is_verified = True
        db.session.commit()
        flash(f'Professional {professional.full_name} has been verified', 'success')
    
    return redirect(url_for('admin_professionals'))

@app.route('/admin/professionals/view/<int:professional_id>')
def admin_view_professional(professional_id):
    if 'user_type' not in session or session['user_type'] != 'admin':
        flash('Please login as admin first', 'danger')
        return redirect(url_for('admin_login'))
    
    professional = Professional.query.get_or_404(professional_id)
    return render_template('admin/view_professional.html', professional=professional)

@app.route('/professional/services', methods=['GET'])
def professional_services():
    if 'user_type' not in session or session['user_type'] != 'professional':
        flash('Please login to access your services', 'warning')
        return redirect(url_for('professional_login'))
    
    try:
        professional = Professional.query.get_or_404(session['user_id'])
        all_services = Service.query.all()
        professional_services = ProfessionalService.query.filter_by(
            professional_id=professional.professional_id
        ).all()
        
        # Create a dict of service_id: price for easy lookup
        current_services = {ps.service_id: ps.price for ps in professional_services}
        
        return render_template('professional/services.html',
                             professional=professional,
                             all_services=all_services,
                             current_services=current_services)
                             
    except Exception as e:
        print(f"Services error: {str(e)}")
        flash('Error loading services', 'danger')
        return redirect(url_for('professional_dashboard'))

@app.route('/professional/services/update', methods=['POST'])
def update_professional_services():
    if 'user_id' not in session or session['user_type'] != 'professional':
        flash('Please login to update services', 'warning')
        return redirect(url_for('professional_login'))
    
    try:
        professional_id = session['user_id']
        
        # Get all submitted services and prices
        services = request.form.getlist('service')
        prices = request.form.getlist('price')
        
        # Delete existing services
        ProfessionalService.query.filter_by(professional_id=professional_id).delete()
        
        # Add new services
        for service_id, price in zip(services, prices):
            if price.strip():  # Only add if price is provided
                new_service = ProfessionalService(
                    professional_id=professional_id,
                    service_id=int(service_id),
                    price=float(price)
                )
                db.session.add(new_service)
        
        db.session.commit()
        flash('Services updated successfully', 'success')
        
    except Exception as e:
        db.session.rollback()
        print(f"Service update error: {str(e)}")
        flash('Error updating services', 'danger')
    
    return redirect(url_for('professional_services'))

@app.route('/professional/bookings')
def professional_bookings():
    if 'user_type' not in session or session['user_type'] != 'professional':
        flash('Please login as professional first', 'danger')
        return redirect(url_for('professional_login'))
    
    professional = Professional.query.get(session['user_id'])
    
    if not professional:
        flash('Professional not found', 'danger')
        return redirect(url_for('professional_login'))
    
    # Get all bookings (service requests) for this professional
    bookings = ServiceRequest.query.filter_by(
        professional_id=professional.professional_id
    ).order_by(ServiceRequest.request_date.desc()).all()
    
    # Load related data to avoid N+1 queries
    bookings = ServiceRequest.query.filter_by(
        professional_id=professional.professional_id
    ).options(
        joinedload(ServiceRequest.customer),
        joinedload(ServiceRequest.service)
    ).order_by(ServiceRequest.request_date.desc()).all()
    
    return render_template('professional/bookings.html',
                         professional=professional,
                         bookings=bookings)

@app.route('/admin/services/add', methods=['GET', 'POST'])
def add_service():
    if 'user_type' not in session or session['user_type'] != 'admin':
        flash('Please login as admin first', 'danger')
        return redirect(url_for('admin_login'))
    
    if request.method == 'POST':
        try:
            # Log the incoming form data
            app.logger.info(f"Form data received: {request.form}")
            
            service_name = request.form.get('service_name', '').strip()
            description = request.form.get('description', '').strip()
            base_price = request.form.get('base_price', '')
            category = request.form.get('category', '').strip()  # Added category field
            
            # Log the processed data
            app.logger.info(f"Processed data: name={service_name}, desc={description}, price={base_price}, category={category}")
            
            # Validate inputs
            if not service_name:
                raise ValueError("Service name is required")
            if not description:
                raise ValueError("Description is required")
            if not base_price:
                raise ValueError("Base price is required")
            if not category:
                raise ValueError("Category is required")
            
            # Convert price to float and validate
            try:
                base_price = float(base_price)
                if base_price <= 0:
                    raise ValueError("Price must be greater than 0")
            except ValueError as e:
                app.logger.error(f"Price conversion error: {str(e)}")
                raise ValueError("Invalid price format")
            
            # Check if service name already exists
            existing_service = Service.query.filter_by(service_name=service_name).first()
            if existing_service:
                raise ValueError("A service with this name already exists")
            
            # Create new service
            new_service = Service(
                service_name=service_name,
                description=description,
                base_price=base_price,
                category=category
            )
            
            # Log the new service object
            app.logger.info(f"Created service object: {new_service}")
            
            # Add and commit to database
            db.session.add(new_service)
            db.session.commit()
            
            flash('Service added successfully', 'success')
            return redirect(url_for('admin_services'))
            
        except ValueError as e:
            app.logger.warning(f"Validation error: {str(e)}")
            flash(str(e), 'danger')
            return redirect(url_for('add_service'))
        except Exception as e:
            db.session.rollback()
            app.logger.error(f"Unexpected error adding service: {str(e)}")
            app.logger.error(f"Error type: {type(e)}")
            app.logger.exception("Full traceback:")
            flash('An unexpected error occurred while adding the service. Please check the logs.', 'danger')
            return redirect(url_for('add_service'))
    
    return render_template('admin/add_service.html')

@app.before_request
def make_session_permanent():
    session.permanent = True
    app.permanent_session_lifetime = timedelta(days=5)

@app.route('/service/book/<int:service_id>', methods=['GET', 'POST'])
def book_service(service_id):
    if 'user_id' not in session or session['user_type'] != 'customer':
        flash('Please login to book a service', 'warning')
        return redirect(url_for('customer_login'))
    
    try:
        service = Service.query.get_or_404(service_id)
        
        # Get professionals and their services
        professionals = Professional.query.join(ProfessionalService)\
            .filter(
                ProfessionalService.service_id == service_id,
                Professional.is_verified == True
            ).all()
        
        # Get professional services as a dictionary for easy lookup
        professional_services = {
            (ps.professional_id, ps.service_id): ps 
            for ps in ProfessionalService.query.filter_by(service_id=service_id).all()
        }
        
        if request.method == 'POST':
            professional_id = request.form.get('professional_id')
            service_date = request.form.get('service_date')
            service_time = request.form.get('service_time')
            notes = request.form.get('notes', '')

            if not all([professional_id, service_date, service_time]):
                flash('Please fill in all required fields', 'danger')
                return redirect(url_for('book_service', service_id=service_id))

            try:
                # Parse the date and time
                service_datetime = datetime.strptime(f"{service_date} {service_time}", "%Y-%m-%d %H:%M")
                
                if service_datetime < datetime.now():
                    flash('Cannot select a past date and time', 'danger')
                    return redirect(url_for('book_service', service_id=service_id))

                # Create new service request
                new_request = ServiceRequest(
                    customer_id=session['user_id'],
                    service_id=service_id,
                    professional_id=professional_id,
                    request_date=service_datetime.date(),
                    request_time=service_datetime.time(),
                    notes=notes,
                    status='Pending'
                )
                
                db.session.add(new_request)
                db.session.commit()
                
                flash('Service booked successfully!', 'success')
                return redirect(url_for('customer_dashboard'))
                
            except ValueError:
                flash('Invalid date or time format', 'danger')
                return redirect(url_for('book_service', service_id=service_id))
            
        today = date.today().isoformat()
        return render_template('customer/book_service.html', 
                             service=service, 
                             professionals=professionals,
                             professional_services=professional_services,
                             today=today)
                             
    except Exception as e:
        db.session.rollback()
        print(f"Booking error: {str(e)}")
        flash('Error processing booking', 'danger')
        return redirect(url_for('customer_dashboard'))

@app.route('/customer/rate/<int:request_id>', methods=['GET', 'POST'])
def rate_professional(request_id):
    if 'user_id' not in session or session['user_type'] != 'customer':
        flash('Please login to rate a professional', 'warning')
        return redirect(url_for('customer_login'))
    
    try:
        service_request = ServiceRequest.query.get_or_404(request_id)
        
        # Verify this request belongs to the logged-in customer
        if service_request.customer_id != session['user_id']:
            flash('Unauthorized action', 'danger')
            return redirect(url_for('customer_dashboard'))
            
        # Check if service is completed
        if service_request.status != 'Completed':
            flash('You can only rate completed services', 'warning')
            return redirect(url_for('customer_dashboard'))
            
        # Check if already rated
        existing_rating = ProfessionalRating.query.filter_by(
            service_request_id=request_id
        ).first()
        
        if existing_rating:
            flash('You have already rated this service', 'warning')
            return redirect(url_for('customer_dashboard'))
        
        if request.method == 'POST':
            rating = request.form.get('rating', type=int)
            review = request.form.get('review', '').strip()
            
            if not rating or rating < 1 or rating > 5:
                flash('Please provide a valid rating (1-5)', 'danger')
                return redirect(url_for('rate_professional', request_id=request_id))
            
            # Create new rating
            new_rating = ProfessionalRating(
                service_request_id=request_id,
                professional_id=service_request.professional_id,
                customer_id=session['user_id'],
                rating=rating,
                review=review
            )
            
            db.session.add(new_rating)
            
            # Update professional's average rating
            professional = service_request.professional
            professional.update_rating()
            
            db.session.commit()
            
            flash('Thank you for your rating!', 'success')
            return redirect(url_for('customer_dashboard'))
        
        return render_template('customer/rate_professional.html', 
                             service_request=service_request)
                             
    except Exception as e:
        db.session.rollback()
        print(f"Rating error: {str(e)}")
        flash('Error processing rating', 'danger')
        return redirect(url_for('customer_dashboard'))

@app.route('/customer/services')
def customer_services():
    if 'user_id' not in session or session['user_type'] != 'customer':
        flash('Please login first', 'warning')
        return redirect(url_for('customer_login'))
        
    try:
        services = Service.query.all()
        return render_template('customer/services.html', services=services)
    except Exception as e:
        print(f"Error loading services: {str(e)}")
        flash('Error loading services', 'danger')
        return redirect(url_for('customer_dashboard'))

@app.route('/update_db')
def update_db():
    try:
        # Add new columns to service_requests table
        with app.app_context():
            db.engine.execute('ALTER TABLE service_requests ADD COLUMN accepted_at DATETIME')
            db.engine.execute('ALTER TABLE service_requests ADD COLUMN completed_at DATETIME')
            db.engine.execute('ALTER TABLE service_requests ADD COLUMN rejected_at DATETIME')
        return 'Database updated successfully'
    except Exception as e:
        return f'Error updating database: {str(e)}'
